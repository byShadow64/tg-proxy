"""Isolated public fixture tests; no real server/source copy or APK build."""
from pathlib import Path
import hashlib
import json
import tempfile
import unittest

from prepare_helper_assets import allowed_paths, prepare


class PayloadAssetsTest(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        source = root / "source"
        for name in allowed_paths():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("synthetic public source " + name + "\r\n").encode())
        (source / "utils").mkdir(exist_ok=True)
        # The builder must inspect this declaration without executing project code.
        (source / "utils/helper_payload.py").write_text(
            "raise RuntimeError('MUST_NOT_EXECUTE')\nHELPER_PAYLOAD_FILES = " + repr(allowed_paths()) + "\n", encoding="utf-8")
        return source

    def temp(self):
        value = tempfile.TemporaryDirectory(prefix="tgproxy-public-assets-test-")
        path = Path(value.name).resolve()
        self.assertTrue(path.is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.assertTrue(path.name.startswith("tgproxy-public-assets-test-"))
        self.addCleanup(value.cleanup)
        return path

    def test_exact_public_files_hashes_normalized_without_executing_module_or_copying_secrets(self):
        root = self.temp(); source = self.fixture(root)
        (source / "private.key").write_text("synthetic-secret-never-package", encoding="utf-8")
        report = prepare(source, root / "output")
        manifest = json.loads((root / "output/manifest.json").read_text())
        self.assertEqual(27, len(manifest["files"]))
        for item in manifest["files"]:
            content = (root / "output" / item["path"]).read_bytes()
            self.assertNotIn(b"\r\n", content)
            self.assertEqual(len(content), item["size"])
            self.assertEqual(hashlib.sha256(content).hexdigest(), item["sha256"])
            self.assertNotIn(b"synthetic-secret-never-package", content)
        self.assertFalse((root / "output/private.key").exists())
        self.assertEqual(report["manifest_sha256"], hashlib.sha256((root / "output/manifest.json").read_bytes()).hexdigest())

    def test_authoritative_list_drift_and_existing_extra_output_fail_closed(self):
        root = self.temp(); source = self.fixture(root)
        (source / "utils/helper_payload.py").write_text("HELPER_PAYLOAD_FILES = ('deploy_helper.sh',)\n")
        with self.assertRaises(ValueError): prepare(source, root / "output")
        self.assertFalse((root / "output").exists())
        source = self.fixture(root)
        (root / "output").mkdir(); (root / "output/private.key").write_text("leave-me")
        with self.assertRaises(ValueError): prepare(source, root / "output")
        self.assertEqual("leave-me", (root / "output/private.key").read_text())

    def test_missing_helper_module_never_leaves_a_partial_output(self):
        root = self.temp(); source = self.fixture(root)
        (source / "proxy/registry_protocol.py").unlink()
        with self.assertRaises(ValueError): prepare(source, root / "output")
        self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
