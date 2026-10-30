"""Offline tests only: generated fixture keys, fake SFTP/HTTPS, no credentials or network."""
from __future__ import annotations

import base64
import errno
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import time
import types
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publisher = load("publication_fixture", "publish-update.py")
prep = publisher.prepare


class MemoryFile(io.BytesIO):
    def __init__(self, sftp, path, data=b"", writing=False):
        super().__init__(data)
        self.sftp, self.path, self.writing = sftp, path, writing

    def flush(self):
        if self.writing and not self.closed:
            self.sftp.files[self.path] = self.getvalue()
        super().flush()

    def close(self):
        if self.writing and not self.closed:
            self.sftp.files[self.path] = self.getvalue()
        super().close()


class FakeSftp:
    def __init__(self):
        self.directories = {"/", "/updates", "/updates/candidate"}
        self.files = {"/updates/latest.json": b"windows-stable-original",
                      "/updates/candidate/latest.json": b"windows-candidate-original"}
        self.symbolic = set()
        self.writes = []
        self.atomic = []
        self.before_rename = None

    def lstat(self, path):
        if path in self.symbolic:
            return types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_size=0)
        if path in self.directories:
            return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_size=0)
        if path in self.files:
            return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_size=len(self.files[path]))
        raise FileNotFoundError(errno.ENOENT, "fixture missing")

    def normalize(self, path):
        return path

    def mkdir(self, path, mode=0o755):
        if path in self.directories or path in self.files:
            raise FileExistsError(errno.EEXIST, "fixture exists")
        if path.rsplit("/", 1)[0] not in self.directories:
            raise FileNotFoundError(errno.ENOENT, "fixture parent")
        self.directories.add(path)

    def chmod(self, path, mode):
        pass

    def open(self, path, mode, bufsize=-1):
        if mode == "rb":
            return MemoryFile(self, path, self.files[path])
        if mode == "wx":
            if path in self.files:
                raise FileExistsError(errno.EEXIST, "fixture exists")
            self.files[path] = b""
            self.writes.append(path)
            return MemoryFile(self, path, writing=True)
        raise AssertionError("Unexpected mode")

    def get_channel(self):
        return self

    def settimeout(self, value):
        pass

    def listdir(self, path):
        prefix = path + "/"
        return [p[len(prefix):] for p in self.files if p.startswith(prefix) and "/" not in p[len(prefix):]]

    def rename(self, old, new):
        if new in self.files:
            raise FileExistsError(errno.EEXIST, "immutable")
        self.files[new] = self.files.pop(old)

    def posix_rename(self, old, new):
        if self.before_rename:
            self.before_rename(old, new)
        self.atomic.append((old, new))
        self.files[new] = self.files.pop(old)

    def remove(self, path):
        del self.files[path]

    def rmdir(self, path):
        self.directories.remove(path)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.apk = b"synthetic-public-apk-bytes"
        digest = hashlib.sha256(self.apk).hexdigest()
        self.data = dict(v=1, package_name=prep.PACKAGE, channel="dev", version_code=7,
                         version_name="0.1.6-dev", min_sdk=26,
                         apk_path=f"/android-dev/releases/7/{digest}.apk",
                         size=len(self.apk), sha256=digest, signer_sha256=prep.SIGNER,
                         notes_ru="Проверка обновления.", notes_en="Update verification.",
                         published_at=int(time.time()))
        self.encoded = self.envelope(self.data)

    def envelope(self, data, raw=None, domain=prep.DOMAIN):
        raw = prep.canonical(data) if raw is None else raw
        return prep.canonical(dict(v=1, key_id=prep.KEY_ID, payload=base64.b64encode(raw).decode(),
                                   signature=base64.b64encode(self.key.sign(domain + raw)).decode())) + b"\n"

    def verify(self, encoded):
        return prep.verify_manifest(encoded, trusted_key=self.public)

    def fetcher(self, sftp):
        def fetch(path, maximum, expected_size=None, **_):
            result = sftp.files["/updates" + path]
            self.assertLessEqual(len(result), maximum)
            if expected_size is not None:
                self.assertEqual(len(result), expected_size)
            return result
        return fetch

    def publish(self, sftp, candidate=False, encoded=None, data=None, fetch=None):
        return publisher.publish_sftp(sftp, data or self.data, encoded or self.encoded, self.apk,
            candidate=candidate, verify_manifest=self.verify, fetch=fetch or self.fetcher(sftp))

    def test_kotlin_registry_canonical_ascii_vector(self):
        # Exact bytes shared with RegistryJson.canonical: ASCII, sorted keys, lowercase escapes.
        self.assertEqual(b'{"n":7,"text":"\\u041f\\u0440\\u0438\\u0432\\u0435\\u0442","v":1}',
                         prep.canonical({"v": 1, "text": "Привет", "n": 7}))
        self.assertEqual(self.data, self.verify(self.encoded))

    def test_wrong_domain_and_payload_tampering_rejected(self):
        with self.assertRaises(prep.UpdateError):
            self.verify(self.envelope(self.data, domain=b"WINDOWS_UPDATE"))
        changed = dict(self.data, version_name="0.1.7-dev")
        outer = json.loads(self.encoded)
        outer["payload"] = base64.b64encode(prep.canonical(changed)).decode()
        with self.assertRaises(prep.UpdateError):
            self.verify(prep.canonical(outer))

    def test_duplicate_keys_noncanonical_and_noncanonical_base64_rejected(self):
        for raw in [b'{"v":1,"v":1}', json.dumps(self.data, ensure_ascii=False).encode()]:
            with self.assertRaises(prep.UpdateError):
                self.verify(self.envelope(self.data, raw=raw))
        outer = json.loads(self.encoded)
        outer["signature"] += "\n"
        with self.assertRaises(prep.UpdateError):
            self.verify(prep.canonical(outer))

    def test_schema_rejects_wrong_signer_traversal_future_control_and_bool(self):
        for change in [dict(signer_sha256="00" * 32), dict(apk_path="/android-dev/../app.apk"),
                       dict(published_at=int(time.time()) + 86460), dict(notes_ru="bad\nparagraph"),
                       dict(version_code=True), dict(notes_en="bad\u202etext"), dict(min_sdk=25)]:
            with self.assertRaises(prep.UpdateError):
                self.verify(self.envelope(dict(self.data, **change)))

    def test_receipt_requires_exact_validation_and_identity(self):
        metadata = dict(version="0.1.6-dev", versionCode=7, minSdk=26, signerSha256=prep.SIGNER, nondebuggable=True)
        receipt = dict(validation_passed=True, version="0.1.6-dev", versionCode=7,
                       size=len(self.apk), sha256=self.data["sha256"], buildSourceCommit="ab" * 20)
        prep.validated_receipt(receipt, metadata, self.apk)
        for change in [dict(validation_passed=False), dict(versionCode=8), dict(size=1),
                       dict(sha256="00" * 32), dict(nondebuggable=False)]:
            with self.assertRaises(prep.UpdateError):
                prep.validated_receipt(dict(receipt, **change), metadata, self.apk)

    def test_bundle_rejects_changed_apk_extra_files_and_checksums(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "manifest.json").write_bytes(self.encoded)
            (folder / "app.apk").write_bytes(self.apk)
            (folder / "SHA256SUMS.txt").write_bytes(prep.checksums(self.encoded, self.apk))
            self.assertEqual(self.data, prep.load_bundle(folder, trusted_key=self.public)[0])
            (folder / "app.apk").write_bytes(self.apk + b"x")
            with self.assertRaises(prep.UpdateError):
                prep.load_bundle(folder, trusted_key=self.public)
            (folder / "app.apk").write_bytes(self.apk)
            (folder / "secret.txt").write_bytes(b"fixture")
            with self.assertRaises(prep.UpdateError):
                prep.load_bundle(folder, trusted_key=self.public)

    def test_candidate_then_dev_reuses_exact_asset_and_preserves_windows(self):
        sftp = FakeSftp()
        original = {p: sftp.files[p] for p in publisher.WINDOWS_METADATA}
        candidate = self.publish(sftp, True)
        self.assertFalse(candidate["reused_apk"])
        production = self.publish(sftp)
        self.assertTrue(production["reused_apk"])
        count = len(sftp.writes)
        self.assertTrue(self.publish(sftp)["reused_apk"])
        self.assertEqual(count, len(sftp.writes))
        self.assertEqual(original, {p: sftp.files[p] for p in publisher.WINDOWS_METADATA})
        self.assertEqual(2, len(sftp.atomic))
        self.assertNotIn("/updates/android-dev/.publisher-lock", sftp.directories)

    def test_immutable_asset_conflict_and_same_code_conflict_fail(self):
        sftp = FakeSftp()
        self.publish(sftp)
        destination = "/updates" + self.data["apk_path"]
        sftp.files[destination] = b"tampered"
        with self.assertRaises(prep.UpdateError) as caught:
            self.publish(sftp)
        self.assertEqual("immutable_apk_conflict", caught.exception.code)
        other = dict(self.data, sha256="00" * 32, apk_path="/android-dev/releases/7/" + "00" * 32 + ".apk")
        with self.assertRaises(prep.UpdateError):
            publisher.compatible_existing(self.encoded, other, monotonic=True, verify=self.verify)

    def test_existing_metadata_blocks_downgrade_and_same_code_note_changes(self):
        with self.assertRaises(prep.UpdateError) as caught:
            publisher.compatible_existing(self.encoded, dict(self.data, version_code=6), monotonic=True, verify=self.verify)
        self.assertEqual("downgrade", caught.exception.code)
        with self.assertRaises(prep.UpdateError) as caught:
            publisher.compatible_existing(self.encoded, dict(self.data, notes_en="Other notes"), monotonic=True, verify=self.verify)
        self.assertEqual("metadata_conflict", caught.exception.code)

    def test_failed_public_apk_check_does_not_commit_metadata(self):
        sftp = FakeSftp()
        def bad_fetch(*_, **__):
            return b"wrong"
        with self.assertRaises(prep.UpdateError) as caught:
            self.publish(sftp, fetch=bad_fetch)
        self.assertFalse(caught.exception.committed)
        self.assertNotIn("/updates/android-dev/latest.json", sftp.files)
        self.assertFalse(any(".tmp" in p for p in sftp.files))
        self.assertNotIn("/updates/android-dev/.publisher-lock", sftp.directories)

    def test_post_commit_verification_failure_reports_commit(self):
        sftp = FakeSftp()
        good_fetch = self.fetcher(sftp)
        def fetch(path, *args, **kwargs):
            return b"wrong" if path.endswith("latest.json") else good_fetch(path, *args, **kwargs)
        with self.assertRaises(prep.UpdateError) as caught:
            self.publish(sftp, fetch=fetch)
        self.assertTrue(caught.exception.committed)
        self.assertEqual(self.encoded, sftp.files["/updates/android-dev/latest.json"])

    def test_symlink_and_existing_publication_lock_fail_closed(self):
        for symlink in [False, True]:
            sftp = FakeSftp()
            sftp.directories.add("/updates/android-dev")
            if symlink:
                sftp.symbolic.add("/updates/android-dev")
            else:
                sftp.directories.add("/updates/android-dev/.publisher-lock")
            with self.assertRaises(prep.UpdateError):
                self.publish(sftp)
            self.assertEqual([], sftp.writes)

    def test_signing_is_reproducible_for_exact_payload_and_key(self):
        with patch.object(prep, "TRUSTED_KEY", self.public):
            first = prep.sign_manifest(self.data, self.key, prep.KEY_ID)
            second = prep.sign_manifest(self.data, self.key, prep.KEY_ID)
        self.assertEqual(first, second)
        self.assertEqual(self.data, self.verify(first))
        self.assertLessEqual(len(first), 8192)

    def test_apk_inspector_rejects_debuggable_wrong_package_sdk_and_signer(self):
        import os
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tools = root / "build-tools/35.0.0"
            (tools / "lib").mkdir(parents=True)
            (tools / ("aapt.exe" if os.name == "nt" else "aapt")).touch()
            (tools / "lib/apksigner.jar").touch()
            java = root / "java.exe"
            java.touch()
            good = "package: name='io.github.byshadow64.tgproxy' versionCode='7' versionName='0.1.6-dev'\nsdkVersion:'26'\n"
            signer = "Signer #1 certificate SHA-256 digest: " + prep.SIGNER + "\nVerified using v2 scheme (APK Signature Scheme v2): true\n"
            with patch.object(prep, "_tool", side_effect=[good, "E: manifest", signer]):
                self.assertEqual(7, prep.inspect_apk(root / "app.apk", root, java)["versionCode"])
            for badging in [good + "application-debuggable\n", good.replace("sdkVersion:'26'", "sdkVersion:'25'"),
                            good.replace("io.github.byshadow64.tgproxy", "wrong.package")]:
                with patch.object(prep, "_tool", return_value=badging), self.assertRaises(prep.UpdateError):
                    prep.inspect_apk(root / "app.apk", root, java)
            with patch.object(prep, "_tool", side_effect=[good, "E: manifest", signer.replace(prep.SIGNER, "00" * 32)]), self.assertRaises(prep.UpdateError):
                prep.inspect_apk(root / "app.apk", root, java)
            for xml in ["A: android:testOnly(0x01010272)=(type 0x12)0xffffffff", "A: android:testOnly=unexpected"]:
                with patch.object(prep, "_tool", side_effect=[good, xml]), self.assertRaises(prep.UpdateError) as caught:
                    prep.inspect_apk(root / "app.apk", root, java)
                self.assertEqual("apk_test_only", caught.exception.code)
            with patch.object(prep, "_tool", side_effect=[good, "A: android:testOnly(0x01010272)=(type 0x12)0x0", signer]):
                self.assertEqual(7, prep.inspect_apk(root / "app.apk", root, java)["versionCode"])

    def test_ssh_host_key_is_verified_before_authentication(self):
        import sys
        for matching in [True, False]:
            events = []
            expected = b"exact-public-host-key"
            class Transport:
                def get_remote_server_key(self):
                    events.append("pin")
                    return types.SimpleNamespace(get_name=lambda: "ssh-ed25519",
                        asbytes=lambda: expected if matching else b"wrong-key")
                def auth_publickey(self, username, key):
                    events.append("auth")
                def is_authenticated(self):
                    return True
                def set_keepalive(self, seconds):
                    pass
            transport = Transport()
            def connect(options):
                events.append("connect")
                return transport, object()
            profile = types.SimpleNamespace(base_url=prep.ORIGIN, webroot="/updates",
                host_key_data=base64.b64encode(expected).decode(), host_key_type="ssh-ed25519")
            profiles = types.ModuleType("publisher.profiles")
            profiles.ServerCredentials = lambda: object()
            profiles.load_default_profile = lambda: profile
            profiles.validate_profile = lambda value: value
            server = types.ModuleType("publisher.server")
            server._auth = lambda *_: (types.SimpleNamespace(username="fixture"), object())
            ssh = types.SimpleNamespace(_connect=connect, _open_sftp=lambda *_: FakeSftp(), _close_quietly=lambda _: None)
            utilities = types.ModuleType("utils")
            utilities.ssh_setup = ssh
            with patch.dict(sys.modules, {"publisher.profiles": profiles, "publisher.server": server, "utils": utilities}):
                if matching:
                    with publisher.Connection():
                        pass
                    self.assertEqual(["connect", "pin", "auth"], events)
                else:
                    with self.assertRaises(prep.UpdateError) as caught:
                        with publisher.Connection():
                            pass
                    self.assertEqual("host_key", caught.exception.code)
                    self.assertEqual(["connect", "pin"], events)

    def test_invalid_existing_signature_stops_before_asset_upload(self):
        sftp = FakeSftp()
        sftp.directories.add("/updates/android-dev")
        outer = json.loads(self.encoded)
        outer["signature"] = base64.b64encode(b"x" * 64).decode()
        sftp.files["/updates/android-dev/latest.json"] = prep.canonical(outer)
        with self.assertRaises(prep.UpdateError) as caught:
            self.publish(sftp)
        self.assertEqual("signature", caught.exception.code)
        self.assertEqual([], sftp.writes)

    def test_http_response_requires_android_compatible_framing(self):
        from email.message import Message
        cases = [
            ([("Content-Length", "4")], b"data", True),
            ([("Content-Length", "4"), ("Content-Encoding", "identity")], b"data", True),
            ([], b"data", False),
            ([("Content-Length", "4"), ("Content-Length", "4")], b"data", False),
            ([("Content-Length", "4"), ("Transfer-Encoding", "chunked")], b"data", False),
            ([("Content-Length", "4"), ("Content-Encoding", "gzip")], b"data", False),
            ([("Content-Length", "4,4")], b"data", False),
            ([("Content-Length", "5")], b"data", False),
            ([("Content-Length", "3")], b"data", False),
            ([("Content-Length", "4"), ("Server", "a"), ("Server", "b")], b"data", False),
            ([("Content-Length", "99")], b"data", False),
        ]
        for entries, body, allowed in cases:
            with self.subTest(headers=entries):
                headers = Message()
                for key, value in entries:
                    headers.add_header(key, value)
                class Response(io.BytesIO):
                    status = 200
                    url = prep.ORIGIN + "/android-dev/latest.json"
                    def __init__(self):
                        super().__init__(body)
                        self.headers = headers
                opener = types.SimpleNamespace(open=lambda *_args, **_kw: Response())
                with patch.object(publisher.urllib.request, "build_opener", return_value=opener):
                    if allowed:
                        self.assertEqual(body, publisher.https_bytes("/android-dev/latest.json", 32))
                    else:
                        with self.assertRaises(prep.UpdateError):
                            publisher.https_bytes("/android-dev/latest.json", 32)

    def test_http_redirect_is_not_followed(self):
        with self.assertRaises(prep.UpdateError):
            publisher.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.invalid/")


if __name__ == "__main__":
    unittest.main()
