"""Publisher server operations use fake SSH/HTTP and synthetic credentials."""
import base64
from dataclasses import replace
import io
import json
import threading
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from publisher.bundle import load_bundle
from publisher.profiles import ServerCredentials, ServerProfile
from publisher import server
from tests.test_publisher_bundle import PreparedBundleMixin
from tests.test_update_publication import SFTP, ServerKey, WEBROOT
from utils import ssh_setup


class Response(io.BytesIO):
    status = 200
    def geturl(self):
        return "https://updates.example.invalid/latest.json"
    def read1(self, count):
        return self.read(count)


class PublisherServerTest(PreparedBundleMixin, unittest.TestCase):
    def setUp(self):
        self.prepare_fixture()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.key = Ed25519PrivateKey.generate()
        trusted = {"test": base64.b64encode(self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()}
        self.stack.enter_context(patch("proxy.update_channel.TRUSTED_UPDATE_KEYS", trusted))
        self.stack.enter_context(patch("publisher.trust.verify_approval", return_value={"verified": True}))
        self.stack.enter_context(patch.object(server, "load_signing_key", return_value=(self.key, "test")))
        self.https = self.stack.enter_context(patch.object(server, "_check_https"))
        self.real_public = server._verify_public
        self.public = self.stack.enter_context(patch.object(server, "_verify_public"))
        self.key_identity = ssh_setup._identity(ServerKey())
        self.profile = ServerProfile(host="updates.example.invalid", webroot=WEBROOT,
                                     base_url="https://updates.example.invalid", auth_method="password",
                                     host_key=self.key_identity.fingerprint)
        self.credentials = ServerCredentials(password="SYNTHETIC-PASSWORD-DO-NOT-TRANSMIT")
        self.transport, self.sock = Mock(), Mock()
        self.transport.get_remote_server_key.return_value = ServerKey()
        self.transport.is_authenticated.return_value = True
        self.sftp = SFTP()
        self.connect = self.stack.enter_context(patch.object(ssh_setup, "_connect", return_value=(self.transport, self.sock)))
        self.stack.enter_context(patch.object(ssh_setup, "_open_sftp", return_value=self.sftp))
        self.bundle = load_bundle(self.root)

    def test_same_bundle_is_published_once_then_only_verified_and_reused(self):
        first = server.publish_bundle(self.bundle, self.profile, self.credentials)
        original = self.sftp.nodes[WEBROOT + "/versions/1.14.9/TgWsProxy_windows.exe"][1]
        self.assertEqual("published_and_verified", first["status"])
        self.assertFalse(first["reused_version"])
        with patch.object(self.core, "_write_remote", wraps=self.core._write_remote) as writes:
            second = server.publish_bundle(self.bundle, self.profile, self.credentials)
        self.assertTrue(second["reused_version"])
        self.assertEqual([], second["uploaded_files"])
        self.assertTrue(all("/.latest." in call.args[1] for call in writes.call_args_list))
        self.assertEqual(original, self.sftp.nodes[WEBROOT + "/versions/1.14.9/TgWsProxy_windows.exe"][1])

    def test_server_and_cli_share_size_aware_transfer_budget(self):
        with patch.object(self.core, "transfer_timeout_for_size", return_value=432) as budget:
            server.publish_bundle(self.bundle, self.profile, self.credentials)
        budget.assert_called_once_with(sum(self.bundle.asset_sizes.values()))
        self.assertEqual(432, self.connect.call_args.args[0].command_timeout)

    def test_wrong_pin_cannot_send_password_or_create_files(self):
        with self.assertRaises(server.ServerError) as caught:
            server.publish_bundle(self.bundle, replace(self.profile, host_key="SHA256:" + "a" * 43), self.credentials)
        self.assertEqual("host_key_mismatch", caught.exception.code)
        self.transport.auth_password.assert_not_called()
        self.transport.auth_publickey.assert_not_called()
        self.assertNotIn("SYNTHETIC-PASSWORD", str(caught.exception))
        self.assertEqual([], self.sftp.events)

    def test_tls_failure_precedes_ssh_authentication(self):
        self.https.side_effect = server.ServerError("https")
        with self.assertRaises(server.ServerError):
            server.publish_bundle(self.bundle, self.profile, self.credentials)
        self.connect.assert_not_called()

    def test_signed_approval_required_before_ssh(self):
        from publisher.trust import TrustError
        with patch("publisher.trust.verify_approval", side_effect=TrustError("approval_required")):
            with self.assertRaises(TrustError):
                server.publish_bundle(self.bundle, self.profile, self.credentials)
        self.connect.assert_not_called()

    def test_newly_signed_manifest_cannot_substitute_approved_bytes_or_notes(self):
        real_build = self.core.build_signed_manifest
        for changed in ("hash", "size", "notes"):
            with self.subTest(changed=changed):
                def altered(*args, **kwargs):
                    envelope = json.loads(real_build(*args, **kwargs))
                    payload = envelope["payload"]
                    if changed == "hash":
                        payload["assets"][0]["sha256"] = "0" * 64
                    elif changed == "size":
                        payload["assets"][0]["size"] += 1
                    else:
                        payload["notes"] = "Different, unapproved release notes"
                    unsigned = {key: envelope[key] for key in ("schema", "key_id", "payload")}
                    envelope["signature"] = base64.b64encode(self.key.sign(self.core.canonical_json(unsigned))).decode()
                    return self.core.canonical_json(envelope)
                with patch.object(self.core, "build_signed_manifest", side_effect=altered), patch.object(
                        self.core, "publish_release") as publish:
                    with self.assertRaises(server.ServerError) as caught:
                        server.publish_bundle(self.bundle, self.profile, self.credentials)
                    self.assertEqual("bundle_changed", caught.exception.code)
                    publish.assert_not_called()
                self.connect.assert_not_called()
                self.assertEqual([], self.sftp.events)

    def test_cancel_during_upload_cleans_owned_paths_and_preserves_latest(self):
        stopped = threading.Event()
        events = []
        def emit(event):
            events.append(event)
            if event["phase"] == "uploading":
                stopped.set()
        with self.assertRaises(server.ServerError) as caught:
            server.publish_bundle(self.bundle, self.profile, self.credentials, emit=emit, cancel=stopped)
        self.assertEqual("cancelled", caught.exception.code)
        self.assertNotIn(WEBROOT + "/latest.json", self.sftp.nodes)
        self.assertNotIn(WEBROOT + "/.publish.lock", self.sftp.nodes)
        self.assertFalse(any(".tmp" in name or "/versions/1.14.9" in name for name in self.sftp.nodes))
        self.assertNotIn(self.credentials.password, json.dumps(events))
        self.assertTrue(all(set(event) <= {"phase", "bytes", "total", "code"} for event in events))

    def test_cancel_after_commit_reports_pending_verification_honestly(self):
        stopped = threading.Event()
        def emit(event):
            if event["phase"] == "published":
                stopped.set()
        self.public.side_effect = server.ServerError("cancelled")
        report = server.publish_bundle(self.bundle, self.profile, self.credentials, emit=emit, cancel=stopped)
        self.assertEqual("published_verification_pending", report["status"])
        self.assertFalse(report["public_verified"])
        self.assertIn(WEBROOT + "/latest.json", self.sftp.nodes)

    def test_readonly_server_check_does_not_claim_write_or_mutate(self):
        result = server.check_server(self.profile, self.credentials)
        self.assertTrue(result["sftp_verified"])
        self.assertFalse(result["write_verified"])
        self.assertEqual([], [e for e in self.sftp.events if e[0] != "open"])

    def test_lost_atomic_rename_reply_is_unconfirmed_and_never_retried(self):
        original = self.sftp.posix_rename
        def lost_reply(source, destination):
            original(source, destination)
            raise OSError("synthetic private connection failure")
        with patch.object(self.sftp, "posix_rename", side_effect=lost_reply) as rename:
            with self.assertRaises(server.ServerError) as caught:
                server.publish_bundle(self.bundle, self.profile, self.credentials)
        self.assertEqual(caught.exception.code, "publication_unconfirmed")
        self.assertFalse(caught.exception.committed, "Commit success must not be asserted without acknowledgement")
        self.assertIn(WEBROOT + "/latest.json", self.sftp.nodes)
        self.assertEqual(rename.call_count, 1)
        self.public.assert_not_called()
        self.assertNotIn("private", str(caught.exception))

    def test_readonly_public_verification_reports_newer_latest_without_writes(self):
        with patch("utils.update_check.fetch_backup_release", return_value={"latest": "1.14.10"}):
            report = server.verify_publication(self.bundle, self.profile)
        self.assertEqual("different_version", report["status"])
        self.assertEqual("1.14.10", report["current_version"])
        self.connect.assert_not_called()

    def test_public_stream_hash_mismatch_is_detected(self):
        release = {"latest": "1.14.9", "assets": [{"name": name,
            "url": "https://updates.example.invalid/versions/1.14.9/" + name,
            "size": path.stat().st_size, "digest": "sha256:" + self.bundle.manifest["assets"][name]}
            for name, path in self.bundle.assets.items()]}
        # _response_url must receive a valid HTTPS URL; the synthetic response
        # contents deliberately fail the signed expected hash/size.
        with patch.object(server, "_verify_public", self.real_public), patch(
                "utils.update_check.fetch_backup_release", return_value=release), patch(
                "utils.update_check._open_response", side_effect=lambda *a, **k: Response(b"corrupted")):
            with self.assertRaises(server.ServerError) as caught:
                server.verify_publication(self.bundle, self.profile)
        self.assertEqual("public_verification", caught.exception.code)
        self.assertFalse(caught.exception.committed)

    def test_public_stream_verification_and_cancel_are_readonly(self):
        release = {"latest": "1.14.9", "assets": [{"name": name,
            "url": "https://updates.example.invalid/versions/1.14.9/" + name,
            "size": path.stat().st_size, "digest": "sha256:" + self.bundle.manifest["assets"][name]}
            for name, path in self.bundle.assets.items()]}
        data = {a["url"]: self.bundle.assets[a["name"]].read_bytes() for a in release["assets"]}
        with patch.object(server, "_verify_public", self.real_public), patch(
                "utils.update_check.fetch_backup_release", return_value=release), patch(
                "utils.update_check._open_response", side_effect=lambda url, **kw: Response(data[url])):
            result = server.verify_publication(self.bundle, self.profile)
        self.assertTrue(result["public_verified"])
        stopped = threading.Event()
        def emit(event):
            if event["phase"] == "verifying_public" and event.get("bytes"):
                stopped.set()
        with patch.object(server, "_verify_public", self.real_public), patch(
                "utils.update_check.fetch_backup_release", return_value=release), patch(
                "utils.update_check._open_response", side_effect=lambda url, **kw: Response(data[url])):
            with self.assertRaises(server.ServerError) as caught:
                server.verify_publication(self.bundle, self.profile, emit=emit, cancel=stopped)
        self.assertEqual("cancelled", caught.exception.code)
        self.assertFalse(caught.exception.committed)
        self.connect.assert_not_called()
