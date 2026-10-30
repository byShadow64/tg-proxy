from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseWorkflowTests(unittest.TestCase):
    def test_release_uses_trusted_default_branch_and_exact_input_without_rebuild(self):
        source = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
        self.assertIn("TGPROXY_EXACT_BUNDLE_PUBLISHER_V1", source)
        self.assertIn("workflow_dispatch:", source)
        self.assertNotIn("  push:", source)
        self.assertNotIn("pull_request_target", source)
        self.assertNotIn("--clobber", source)
        self.assertNotIn("PyInstaller", source)
        self.assertNotIn("pip install \".", source)
        self.assertNotIn("verify_windows_exe.py", source)
        self.assertIn("--verify-only", source)
        self.assertIn("--publish --create-missing-tag", source)
        self.assertIn("needs: verify", source)
        self.assertIn("cancel-in-progress: false", source)
        self.assertIn("--only-binary=:all: --require-hashes", source)
        self.assertEqual(source.count("ref: ${{ github.sha }}"), 2)
        self.assertEqual(source.count("persist-credentials: false"), 2)
        for action in re.findall(r"uses:\s*([^\s#]+)", source):
            self.assertRegex(action, r"^actions/[a-z-]+@[0-9a-f]{40}$")

    def test_unsigned_ci_bundle_is_separate_from_publication(self):
        source = (ROOT / ".github/workflows/windows-ci.yml").read_text(encoding="utf-8")
        self.assertIn("contents: read", source)
        self.assertNotIn("contents: write", source)
        self.assertIn("--bundle-output dist/publication", source)
        self.assertIn("TgWsProxy-unsigned-publication-bundle", source)
        self.assertNotIn("promote_release.py", source)

    def test_client_channel_identity_was_not_moved_by_publisher_work(self):
        source = (ROOT / "proxy/update_channel.py").read_text(encoding="utf-8")
        self.assertIn('UPDATE_MANIFEST_URL = "https://217.177.34.28/latest.json"', source)


if __name__ == "__main__":
    unittest.main()
