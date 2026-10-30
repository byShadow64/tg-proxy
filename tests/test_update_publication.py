"""Publisher tests use synthetic files and an in-memory SFTP server, never SSH."""
import base64
import errno
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
import zipfile
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from utils import ssh_setup
from utils.update_manifest import canonical_message, verify_manifest


MODULE_PATH = Path(__file__).resolve().parents[1] / "packaging" / "publish_updates.py"
SPEC = importlib.util.spec_from_file_location("test_update_publisher", MODULE_PATH)
publisher = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publisher
SPEC.loader.exec_module(publisher)
VERSION = "1.14.0"
BASE_URL = "https://updates.example.invalid/tg-proxy"
WEBROOT = "/srv/updates"


class Writer(io.BytesIO):
    def __init__(self, owner, path):
        super().__init__()
        self.owner, self.path = owner, path
        self.pipelined = False

    def set_pipelined(self, pipelined=True):
        self.pipelined = pipelined
        self.owner.events.append(("pipeline", self.path))

    def write(self, data):
        if not self.pipelined:
            raise AssertionError("Publisher writes must be pipelined")
        return super().write(data)

    def close(self):
        if not self.closed:
            if (self.owner.write_close_error_name
                    and self.path.endswith("/" + self.owner.write_close_error_name)):
                super().close()
                raise OSError("synthetic delayed write failure")
            mode, _ = self.owner.nodes[self.path]
            self.owner.nodes[self.path] = (mode, self.getvalue())
        super().close()


class Reader(io.BytesIO):
    def __init__(self, owner, path, data):
        super().__init__(data)
        self.owner, self.path = owner, path

    def prefetch(self, file_size=None, max_concurrent_requests=None):
        if file_size is None or max_concurrent_requests != 16:
            raise AssertionError("Prefetch must have a known endpoint and bounded concurrency")
        if not self.tell() < file_size <= self.tell() + 16 * 32768:
            raise AssertionError("Prefetch worker must fit in one bounded request window")
        self.owner.prefetches.append((self.path, self.tell(), file_size, max_concurrent_requests))


class SFTP:
    def __init__(self):
        self.nodes = {p: (stat.S_IFDIR | 0o755, None) for p in ("/", "/srv", WEBROOT)}
        self.events = []
        self.channel = Mock()
        self.close = Mock()
        self.corrupt_name = None
        self.fail_atomic = False
        self.write_close_error_name = None
        self.prefetches = []

    def get_channel(self):
        return self.channel

    def lstat(self, path):
        if path not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "not found")
        mode, data = self.nodes[path]
        return SimpleNamespace(st_mode=mode, st_size=len(data) if data is not None else 0, st_uid=1001)

    def mkdir(self, path, mode):
        if path in self.nodes:
            raise FileExistsError(errno.EEXIST, "exists")
        if str(Path(path).parent).replace("\\", "/") not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "parent missing")
        self.nodes[path] = (stat.S_IFDIR | mode, None)
        self.events.append(("mkdir", path))

    def chmod(self, path, mode):
        current, data = self.nodes[path]
        self.nodes[path] = (stat.S_IFMT(current) | mode, data)

    def open(self, path, mode, **kwargs):
        self.events.append(("open", path))
        if "w" in mode:
            if path in self.nodes:
                raise FileExistsError(errno.EEXIST, "exists")
            self.nodes[path] = (stat.S_IFREG | 0o644, b"")
            return Writer(self, path)
        if path not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "not found")
        contents = self.nodes[path][1]
        if self.corrupt_name and path.endswith("/" + self.corrupt_name) and ".tmp/" in path:
            contents = b"!" + contents[1:]
        return Reader(self, path, contents)

    def listdir(self, path):
        prefix = path + "/"
        return [p[len(prefix):] for p in self.nodes if p.startswith(prefix) and "/" not in p[len(prefix):]]

    def rename(self, source, destination):
        if destination in self.nodes:
            raise FileExistsError(errno.EEXIST, "exists")
        if source not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "not found")
        moved = {p: value for p, value in self.nodes.items()
                 if p == source or p.startswith(source + "/")}
        for path, value in moved.items():
            self.nodes[destination + path[len(source):]] = value
            del self.nodes[path]
        self.events.append(("rename", destination))

    def posix_rename(self, source, destination):
        if self.fail_atomic:
            raise OSError("extension unsupported")
        self.nodes[destination] = self.nodes.pop(source)
        self.events.append(("posix_rename", destination))

    def remove(self, path):
        if path not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "not found")
        if stat.S_ISDIR(self.nodes[path][0]):
            raise IsADirectoryError(path)
        del self.nodes[path]
        self.events.append(("remove", path))

    def rmdir(self, path):
        if path not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "not found")
        if any(p.startswith(path + "/") for p in self.nodes):
            raise OSError(errno.ENOTEMPTY, "not empty")
        del self.nodes[path]
        self.events.append(("rmdir", path))


class ServerKey:
    def asbytes(self):
        return b"synthetic-server-ed25519-public-key"

    def get_name(self):
        return "ssh-ed25519"


class UpdatePublicationTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        temporary = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.directory = Path(temporary)
        self.files = {n: self.directory / n for n in publisher.ASSET_NAMES}
        self.files["TgWsProxy_windows.exe"].write_bytes(b"MZ-synthetic-executable-v1")
        self.files["CHANGELOG.md"].write_text("# Changes\n\n## 1.14.0\n", encoding="utf-8")
        self.write_helper()
        self.update_checksums()
        self.real_windows_version = publisher._windows_version
        self.pe_version = self.stack.enter_context(patch.object(
            publisher, "_windows_version", return_value=(1, 14, 0, 0)))
        self.private_key = Ed25519PrivateKey.generate()
        self.trusted_keys = {"stable-2026": base64.b64encode(self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")}
        self.server_key = ServerKey()
        self.identity = ssh_setup._identity(self.server_key)
        self.transport, self.sock = Mock(), Mock()
        self.transport.get_remote_server_key.return_value = self.server_key
        self.transport.is_authenticated.return_value = True
        self.options = ssh_setup.SSHOptions("updates.example.invalid", username="publisher",
                                           password="synthetic-password")
        self.sftp = SFTP()
        self.connect = self.stack.enter_context(patch.object(
            ssh_setup, "_connect", return_value=(self.transport, self.sock)))
        self.stack.enter_context(patch.object(ssh_setup, "_open_sftp", return_value=self.sftp))

    def write_helper(self, extra=None):
        with zipfile.ZipFile(self.files["TgWsProxy_helper.zip"], "w") as archive:
            for name in sorted(publisher.HELPER_FILES):
                archive.writestr("TgWsProxy-helper/" + name, "# synthetic source\n")
            if extra:
                archive.writestr(*extra)

    def update_checksums(self):
        self.files["SHA256SUMS.txt"].write_text("".join(
            hashlib.sha256(self.files[n].read_bytes()).hexdigest() + "  " + n + "\n"
            for n in ("TgWsProxy_windows.exe", "TgWsProxy_helper.zip")), encoding="ascii")

    def test_old_helper_archive_remains_valid_but_new_release_requires_pairing_module(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name in sorted(publisher.HELPER_FILES_1151 - {"helper_pairing.py"}):
                archive.writestr("TgWsProxy-helper/" + name, "# synthetic source\n")
        publisher._validate_helper_zip(stream.getvalue(), version="1.15.0")
        with self.assertRaises(publisher.PublicationError):
            publisher._validate_helper_zip(stream.getvalue(), version="1.15.1")

    def test_existing_registry_archive_remains_valid_new_policy_payload_is_required(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name in sorted(publisher.HELPER_FILES_1152):
                archive.writestr("TgWsProxy-helper/" + name, "# synthetic source\n")
        publisher._validate_helper_zip(stream.getvalue(), version="1.15.2")
        with self.assertRaises(publisher.PublicationError):
            publisher._validate_helper_zip(stream.getvalue(), version="1.15.3")
        with self.assertRaises(publisher.PublicationError):
            publisher._validate_helper_zip(stream.getvalue())

    def manifest(self, **kwargs):
        return publisher.build_signed_manifest(VERSION, self.files, BASE_URL,
                                                self.private_key, "stable-2026",
                                                notes="Updates\nИзменения", **kwargs)

    def publish(self, manifest=None, **kwargs):
        return publisher.publish_release(self.options, self.identity, WEBROOT,
                                           self.files, manifest or self.manifest(),
                                           trusted_keys=self.trusted_keys, **kwargs)

    def assert_error(self, code, function, *args, **kwargs):
        with self.assertRaises(publisher.PublicationError) as context:
            function(*args, **kwargs)
        self.assertEqual(code, context.exception.code)

    def test_transfer_budget_accounts_for_both_directions_and_is_bounded(self):
        self.assertEqual(300, publisher.transfer_timeout_for_size(1024))
        self.assertAlmostEqual(485.88128662109375, publisher.transfer_timeout_for_size(27910556))
        self.assertEqual(900, publisher.transfer_timeout_for_size(256 * 1024 * 1024))

    def test_watchdog_thread_start_failure_cannot_contact_server(self):
        with patch.object(publisher.threading.Thread, "start", side_effect=RuntimeError("synthetic")):
            self.assert_error("sftp", self.publish)
        self.connect.assert_not_called()
        self.assertEqual([], self.sftp.events)

    def test_cleanup_timer_start_failure_preserves_error_and_closes_resources(self):
        self.sftp.corrupt_name = "TgWsProxy_windows.exe"
        with patch.object(publisher.threading.Timer, "start", side_effect=RuntimeError("synthetic")):
            self.assert_error("remote_hash", self.publish)
        self.transport.close.assert_called_once()
        self.sftp.close.assert_called_once()
        self.assertNotIn(WEBROOT + "/latest.json", self.sftp.nodes)

    def test_existing_version_cooperative_cancel_is_not_immutable_conflict(self):
        self.publish()
        with patch.object(publisher, "_remote_hash", side_effect=publisher.PublicationError("cancelled")):
            self.assert_error("cancelled", self.publish)

    def test_signature_binds_schema_key_id_and_unicode_payload(self):
        raw = self.manifest()
        envelope = json.loads(raw)
        unsigned = {k: envelope[k] for k in ("schema", "key_id", "payload")}
        signature = base64.b64decode(envelope["signature"], validate=True)
        self.assertEqual(canonical_message(1, "stable-2026", envelope["payload"]),
                         publisher.canonical_json(unsigned))
        self.private_key.public_key().verify(signature, publisher.canonical_json(unsigned))
        verified = verify_manifest(raw, self.trusted_keys)
        self.assertEqual(VERSION, verified["latest"])
        self.assertEqual("backup", verified["source"])
        for key, value in (("schema", 2), ("key_id", "another-key")):
            with self.subTest(key=key):
                changed = dict(unsigned, **{key: value})
                with self.assertRaises(InvalidSignature):
                    self.private_key.public_key().verify(signature, publisher.canonical_json(changed))
        payload = envelope["payload"]
        self.assertEqual(VERSION, payload["version"])
        self.assertEqual(set(publisher.ASSET_NAMES), {a["name"] for a in payload["assets"]})
        self.assertEqual("Updates\nИзменения", payload["notes"])
        published = publisher._parse_timestamp(payload["published_at"])
        self.assertEqual(published + timedelta(days=90), publisher._parse_timestamp(payload["expires_at"]))
        self.assertNotIn(b"PRIVATE KEY", raw)
        for entry in payload["assets"]:
            contents = self.files[entry["name"]].read_bytes()
            self.assertEqual(len(contents), entry["size"])
            self.assertEqual(hashlib.sha256(contents).hexdigest(), entry["sha256"])

    def test_allowlist_rejects_extra_private_config_and_helper_member(self):
        files = dict(self.files, **{"config.json": self.directory / "config.json"})
        self.assert_error("asset_allowlist", publisher.build_signed_manifest,
                          VERSION, files, BASE_URL, self.private_key, "stable")
        self.write_helper(("TgWsProxy-helper/config.json", "synthetic private config"))
        self.update_checksums()
        self.assert_error("helper_archive", self.manifest)

    def test_pe_metadata_must_match_declared_version(self):
        self.pe_version.return_value = (1, 13, 0, 0)
        self.assert_error("pe_version", self.manifest)

    def test_invalid_pe_rejected_by_real_reader(self):
        with patch.object(publisher, "_windows_version", self.real_windows_version):
            self.assert_error("pe_version", self.manifest)

    def test_wrong_checksums_expiry_and_insecure_urls_fail_locally(self):
        self.files["SHA256SUMS.txt"].write_text("0" * 64 + "  TgWsProxy_windows.exe\n", encoding="ascii")
        self.assert_error("checksums", self.manifest)
        self.update_checksums()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.assert_error("expiry", self.manifest, published_at=now,
                          expires_at=now + timedelta(days=91))
        self.assert_error("url", publisher.build_signed_manifest,
                          VERSION, self.files, "http://updates.invalid", self.private_key, "stable")
        self.assert_error("url", self.manifest, page_url="https://user:password@updates.invalid/page")
        self.connect.assert_not_called()

    def test_host_key_checked_before_authentication_or_upload(self):
        wrong = ssh_setup.SSHHostKey("ssh-ed25519", b"different", "SHA256:" + "a" * 43)
        self.assert_error("host_key_mismatch", publisher.publish_release,
                          self.options, wrong, WEBROOT, self.files, self.manifest(),
                          trusted_keys=self.trusted_keys)
        self.transport.auth_password.assert_not_called()
        self.transport.auth_publickey.assert_not_called()
        self.assertEqual([], self.sftp.events)
        self.transport.close.assert_called_once()
        self.sock.close.assert_called_once()

    def test_upload_verifies_assets_then_publishes_latest_atomically(self):
        manifest = self.manifest()
        report = self.publish(manifest)
        self.assertEqual(VERSION, report.version)
        self.assertEqual(set(publisher.ASSET_NAMES), set(report.uploaded_files))
        self.assertFalse(report.reused_version)
        self.assertEqual(manifest, self.sftp.nodes[WEBROOT + "/latest.json"][1])
        for name, source in self.files.items():
            mode, data = self.sftp.nodes[report.version_path + "/" + name]
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(0o644, stat.S_IMODE(mode))
        self.assertEqual(0o755, stat.S_IMODE(self.sftp.nodes[report.version_path][0]))
        mutation_events = [e for e in self.sftp.events if e[0] in ("rename", "posix_rename")]
        self.assertEqual([("rename", report.version_path),
                          ("posix_rename", WEBROOT + "/latest.json")], mutation_events)
        self.assertFalse(any(".tmp" in p or ".latest." in p or ".publish.lock" in p for p in self.sftp.nodes))
        self.assertEqual(5, len([e for e in self.sftp.events if e[0] == "pipeline"]))
        self.assertEqual(5, len(self.sftp.prefetches))

    def test_large_asset_readback_prefetches_bounded_windows(self):
        contents = b"MZ" + b"x" * (3 * 512 * 1024 + 37)
        self.files["TgWsProxy_windows.exe"].write_bytes(contents)
        self.update_checksums()
        self.publish()
        windows = [(start, end, limit) for path, start, end, limit in self.sftp.prefetches
                   if path.endswith("/TgWsProxy_windows.exe")]
        self.assertEqual([(0, 512 * 1024, 16),
                          (512 * 1024, 1024 * 1024, 16),
                          (1024 * 1024, 1536 * 1024, 16),
                          (1536 * 1024, len(contents), 16)], windows)

    def test_delayed_pipelined_write_failure_cannot_publish_latest(self):
        previous = self.manifest()
        self.sftp.nodes[WEBROOT + "/latest.json"] = (stat.S_IFREG | 0o644, previous)
        self.sftp.write_close_error_name = "TgWsProxy_windows.exe"
        self.assert_error("sftp", self.publish)
        self.assertEqual(previous, self.sftp.nodes[WEBROOT + "/latest.json"][1])
        self.assertNotIn(WEBROOT + "/versions/" + VERSION, self.sftp.nodes)
        self.assertFalse(any(".tmp" in path or ".publish.lock" in path for path in self.sftp.nodes))

    def test_key_authentication_and_fingerprint_string_supported(self):
        key = Mock()
        publisher.publish_release(self.options, self.identity.fingerprint, WEBROOT,
                                  self.files, self.manifest(), ssh_private_key=key,
                                  trusted_keys=self.trusted_keys)
        self.transport.auth_publickey.assert_called_once_with("publisher", key)
        self.transport.auth_password.assert_not_called()
        self.sftp.close.assert_called_once()

    def test_readback_corruption_leaves_previous_latest_and_cleans_only_stage(self):
        previous = self.manifest()
        self.sftp.nodes[WEBROOT + "/latest.json"] = (stat.S_IFREG | 0o644, previous)
        self.sftp.nodes[WEBROOT + "/operator.txt"] = (stat.S_IFREG | 0o644, b"untouched")
        self.sftp.corrupt_name = "TgWsProxy_windows.exe"
        self.assert_error("remote_hash", self.publish)
        self.assertEqual(previous, self.sftp.nodes[WEBROOT + "/latest.json"][1])
        self.assertEqual(b"untouched", self.sftp.nodes[WEBROOT + "/operator.txt"][1])
        self.assertNotIn(WEBROOT + "/versions/" + VERSION, self.sftp.nodes)
        self.assertFalse(any(".tmp" in p or ".publish.lock" in p for p in self.sftp.nodes))

    def test_existing_version_same_bytes_reused_and_different_hash_refused(self):
        self.publish()
        report = self.publish()
        self.assertTrue(report.reused_version)
        self.assertEqual((), report.uploaded_files)
        previous = self.sftp.nodes[WEBROOT + "/latest.json"][1]
        self.files["TgWsProxy_windows.exe"].write_bytes(b"MZ-different-synthetic-executable")
        self.update_checksums()
        self.assert_error("immutable_version", self.publish)
        self.assertEqual(previous, self.sftp.nodes[WEBROOT + "/latest.json"][1])

    def test_downgrade_refused_before_version_upload(self):
        self.pe_version.return_value = (1, 15, 0, 0)
        newer = publisher.build_signed_manifest("1.15.0", self.files, BASE_URL,
                                                self.private_key, "stable")
        self.sftp.nodes[WEBROOT + "/latest.json"] = (stat.S_IFREG | 0o644, newer)
        self.pe_version.return_value = (1, 14, 0, 0)
        self.assert_error("downgrade", self.publish)
        self.assertEqual(newer, self.sftp.nodes[WEBROOT + "/latest.json"][1])
        self.assertFalse(any(".tmp" in p for p in self.sftp.nodes))

    def test_busy_lock_preserved_without_upload(self):
        lock = WEBROOT + "/.publish.lock"
        self.sftp.nodes[lock] = (stat.S_IFDIR | 0o700, None)
        before = dict(self.sftp.nodes)
        self.assert_error("busy", self.publish)
        self.assertEqual(before, self.sftp.nodes)

    def test_symlink_webroot_and_manifest_refused(self):
        for path in (WEBROOT, WEBROOT + "/latest.json"):
            with self.subTest(path=path):
                saved = dict(self.sftp.nodes)
                self.sftp.nodes[path] = (stat.S_IFLNK | 0o777, b"/other/location")
                self.assert_error("remote_directory" if path == WEBROOT else "remote_file", self.publish)
                self.sftp.nodes = saved

    def test_missing_atomic_extension_does_not_remove_previous_latest(self):
        previous = self.manifest()
        self.sftp.nodes[WEBROOT + "/latest.json"] = (stat.S_IFREG | 0o644, previous)
        self.sftp.fail_atomic = True
        self.assert_error("publication_unconfirmed", self.publish)
        self.assertEqual(previous, self.sftp.nodes[WEBROOT + "/latest.json"][1])
        self.assertIn(WEBROOT + "/versions/" + VERSION, self.sftp.nodes)
        self.assertNotIn(("remove", WEBROOT + "/latest.json"), self.sftp.events)
        self.assertFalse(any(".latest." in p or ".publish.lock" in p for p in self.sftp.nodes))

    def test_colliding_manifest_temp_is_not_removed(self):
        temporary = WEBROOT + "/.latest." + "a" * 24 + ".json"
        self.sftp.nodes[temporary] = (stat.S_IFREG | 0o644, b"another publisher's file")
        with patch.object(publisher.secrets, "token_hex", return_value="a" * 24):
            self.assert_error("sftp", self.publish)
        self.assertEqual(b"another publisher's file", self.sftp.nodes[temporary][1])
        self.assertNotIn(("remove", temporary), self.sftp.events)

    def test_owned_partial_manifest_removed_if_chmod_fails_after_create(self):
        previous = self.manifest()
        self.sftp.nodes[WEBROOT + "/latest.json"] = (stat.S_IFREG | 0o644, previous)
        original_chmod = self.sftp.chmod

        def fail_manifest_chmod(path, mode):
            if "/.latest." in path:
                raise PermissionError(errno.EACCES, "synthetic denied")
            return original_chmod(path, mode)

        with patch.object(self.sftp, "chmod", side_effect=fail_manifest_chmod):
            self.assert_error("sftp", self.publish)
        self.assertEqual(previous, self.sftp.nodes[WEBROOT + "/latest.json"][1])
        self.assertFalse(any(".latest." in path for path in self.sftp.nodes))

    def test_modified_local_asset_cannot_be_published_under_signed_hash(self):
        manifest = self.manifest()
        self.files["CHANGELOG.md"].write_text("# Different notes", encoding="utf-8")
        self.assert_error("asset_manifest_mismatch", self.publish, manifest)
        self.connect.assert_not_called()

    def test_expired_or_duplicate_json_manifest_rejected_before_ssh(self):
        old = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=100)
        self.assert_error("manifest", self.publish, self.manifest(published_at=old))
        raw = self.manifest().replace(b'"schema":1', b'"schema":1,"schema":1')
        self.assert_error("manifest", self.publish, raw)
        self.connect.assert_not_called()

    def test_private_signing_key_inside_checkout_refused(self):
        self.assert_error("key_inside_checkout", publisher._external_key_path,
                          str(MODULE_PATH.parent / "private.pem"))

    def test_signature_tampering_or_unknown_key_rejected_before_ssh(self):
        for key, value in (("signature", base64.b64encode(b"x" * 64).decode()),
                           ("key_id", "untrusted")):
            with self.subTest(key=key):
                envelope = json.loads(self.manifest())
                envelope[key] = value
                self.assert_error("signature", self.publish, publisher.canonical_json(envelope))
        self.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
