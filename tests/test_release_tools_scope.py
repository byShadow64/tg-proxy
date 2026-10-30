"""Public release helpers exclude local administration and keep the wire contract."""
import ast
from pathlib import Path
import unittest
from unittest.mock import patch

from release_tools import assets, bundle, github, trust
from tests.test_release_bundle import PreparedBundleMixin

ROOT = Path(__file__).resolve().parents[1]


class ReleaseToolsScopeTest(unittest.TestCase):
    def test_public_helpers_are_verifiers_and_actions_promotion_only(self):
        self.assertEqual({p.name for p in (ROOT / "release_tools").glob("*.py")},
                         {"__init__.py", "assets.py", "bundle.py", "trust.py", "github.py"})
        for relative in ("publisher", "publisher_main.py", "packaging/publisher.spec",
                         "packaging/publisher_version_info.txt", "packaging/publish_updates.py",
                         "packaging/publish_local_updates.py", "packaging/deploy_update_server.sh"):
            self.assertFalse((ROOT / relative).exists(), relative)
        for name in ("approve_bundle", "approval_file", "load_approval"):
            self.assertFalse(hasattr(trust, name), name)
        self.assertFalse(hasattr(bundle, "export_bundle"))
        for name in ("prepare_github_draft", "dispatch_release_workflow", "preflight_github",
                     "verify_github_publication"):
            self.assertFalse(hasattr(github, name), name)
        for path in (ROOT / "release_tools").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_bytes())):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or "").startswith(("publisher", "paramiko", "utils.secure_storage")))
                elif isinstance(node, ast.Import):
                    self.assertFalse(any(n.name.startswith(("publisher", "paramiko")) for n in node.names))

    def test_existing_signed_bundle_and_actions_input_protocol_is_preserved(self):
        self.assertEqual(trust.DOMAIN, b"TGPROXY_STABLE_RELEASE_APPROVAL_V1\0")
        self.assertEqual(set(trust.TRUSTED_APPROVAL_KEYS), {"tgproxy-2026-01"})
        self.assertEqual(github.WORKFLOW_MARKER, "TGPROXY_EXACT_BUNDLE_PUBLISHER_V1")
        self.assertEqual(github.INPUT_ASSET, "publication-bundle.zip")
        self.assertEqual(set(bundle.ASSET_NAMES), set(assets.ASSET_NAMES))
        self.assertEqual(set(bundle.ASSET_NAMES), github.ASSETS)
        workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
        for input_name in ("draft_release_id", "bundle_asset_id", "bundle_sha256", "tag"):
            self.assertIn(input_name + ":", workflow)
        self.assertIn("packaging/release-verification-requirements.lock", workflow)
        self.assertNotIn("publisher-requirements.lock", workflow)
        for path in (ROOT / "packaging/prepare_release.py", ROOT / "packaging/promote_release.py"):
            text = path.read_text(encoding="utf-8")
            self.assertIn("from release_tools.", text)
            self.assertNotIn("from publisher", text)


class ReleaseAssetValidationTest(PreparedBundleMixin, unittest.TestCase):
    def setUp(self):
        self.prepare_fixture(version="1.15.3")
        self.files = {name: self.assets / name for name in assets.ASSET_NAMES}

    def error(self, code):
        with self.assertRaises(assets.PublicationError) as caught:
            assets._read_release_files("1.15.3", self.files)
        self.assertEqual(caught.exception.code, code)

    def test_complete_four_files_are_read_without_modification(self):
        expected = {name: path.read_bytes() for name, path in self.files.items()}
        self.assertEqual(assets._read_release_files("1.15.3", self.files), expected)
        self.assertEqual({name: path.read_bytes() for name, path in self.files.items()}, expected)

    def test_unknown_asset_bad_checksum_and_wrong_pe_are_rejected(self):
        self.files["unexpected.json"] = self.root / "unexpected.json"
        self.error("asset_allowlist")
        del self.files["unexpected.json"]
        sums = self.files["SHA256SUMS.txt"]
        before = sums.read_bytes()
        sums.write_text("0" * 64 + "  TgWsProxy_windows.exe\n", encoding="ascii")
        self.error("checksums")
        sums.write_bytes(before)
        with patch.object(assets, "_windows_version", return_value=(1, 15, 3, 1)):
            self.error("pe_version")

    def test_private_material_in_public_notes_is_rejected(self):
        self.files["CHANGELOG.md"].write_bytes(b"PRIVATE SYNTHETIC FIXTURE: -----BEGIN PRIVATE KEY-----")
        self.error("private_material")


if __name__ == "__main__":
    unittest.main()
