"""Only the helper source allowlist may leave a source or frozen client."""
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from utils import helper_payload


class HelperPayloadTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def sources(self, root):
        for name in helper_payload.HELPER_PAYLOAD_FILES:
            source = root / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes((name + "\r\n").encode())

    def test_deterministic_regular_source_only_archive_has_unix_modes_and_lf(self):
        self.sources(self.root)
        (self.root / ".git").mkdir()
        (self.root / ".git" / "config").write_text("do not export credentials")
        (self.root / "config.json").write_text('{"secret":"private-user-config"}')
        payload = helper_payload.build_helper_payload(self.root)
        self.assertEqual(payload, helper_payload.build_helper_payload(self.root))
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            self.assertEqual(archive.getnames(), list(helper_payload.HELPER_PAYLOAD_FILES))
            for member in archive.getmembers():
                self.assertTrue(member.isfile())
                self.assertEqual(member.mode, 0o755 if member.name.endswith(".sh") else 0o644)
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual(archive.extractfile(member).read(), (member.name + "\n").encode())
        self.assertNotIn(b"private-user-config", payload)
        self.assertNotIn(b"do not export credentials", payload)

    def test_missing_source_fails_instead_of_building_partial_payload(self):
        self.sources(self.root)
        (self.root / "helper_server.py").unlink()
        with self.assertRaises(ValueError):
            helper_payload.build_helper_payload(self.root)

    def test_symlink_source_is_rejected(self):
        self.sources(self.root)
        source = self.root / "helper_server.py"
        source.unlink()
        target = self.root / "outside.py"
        target.write_text("unreviewed source")
        try:
            source.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"Symlinks unavailable: {exc}")
        with self.assertRaises(ValueError):
            helper_payload.build_helper_payload(self.root)

    def test_frozen_client_uses_bundled_payload_and_never_needs_github(self):
        self.sources(self.root)
        payload = helper_payload.build_helper_payload(self.root)
        bundle = self.root / "bundle"
        bundle.mkdir()
        (bundle / helper_payload.PAYLOAD_RESOURCE).write_bytes(payload)
        with patch.object(helper_payload.sys, "frozen", True, create=True), \
                patch.object(helper_payload.sys, "_MEIPASS", str(bundle), create=True):
            self.assertEqual(helper_payload.build_helper_payload(), payload)

    def test_installed_wheel_reads_the_force_included_source_directory(self):
        site_packages = self.root / "site-packages"
        self.sources(site_packages / "helper_payload_src")
        with patch.object(helper_payload, "__file__", str(site_packages / "utils" / "helper_payload.py")), \
                patch.object(helper_payload.sys, "frozen", False, create=True):
            payload = helper_payload.build_helper_payload()
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            self.assertEqual(set(archive.getnames()), set(helper_payload.HELPER_PAYLOAD_FILES))
        with self.assertRaises(ValueError):
            helper_payload.build_helper_payload(site_packages)

    def test_tampered_frozen_resource_cannot_add_or_link_to_user_files(self):
        self.sources(self.root)
        original = helper_payload.build_helper_payload(self.root)
        for malicious in ("../config.json", "/etc/shadow", "helper_server.py"):
            stream = io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(original)) as source, \
                    tarfile.open(fileobj=stream, mode="w") as target:
                for member in source.getmembers():
                    if malicious == "helper_server.py" and member.name == malicious:
                        member.type = tarfile.SYMTYPE
                        member.linkname = "/etc/shadow"
                        member.size = 0
                        target.addfile(member)
                    else:
                        target.addfile(member, source.extractfile(member))
                if malicious != "helper_server.py":
                    target.addfile(tarfile.TarInfo(malicious), io.BytesIO())
            bundle = self.root / helper_payload.PAYLOAD_RESOURCE
            bundle.write_bytes(stream.getvalue())
            with self.subTest(member=malicious), \
                    patch.object(helper_payload.sys, "frozen", True, create=True), \
                    patch.object(helper_payload.sys, "_MEIPASS", str(self.root), create=True), \
                    self.assertRaises(ValueError):
                helper_payload.build_helper_payload()
