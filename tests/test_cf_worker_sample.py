"""The canonical Worker stays aligned with client routes; JS tests never use a network."""
import ast
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CfWorkerSampleTest(unittest.TestCase):
    def test_catalogue_matches_client_policy_and_both_instructions_use_same_source(self):
        source = (ROOT / "worker/telegram-worker.mjs").read_text(encoding="utf-8")
        block = source.split("export const TELEGRAM_CIDRS = Object.freeze([", 1)[1].split("]);", 1)[0]
        catalogue = re.findall(r'"([^"\n]+)"', block)
        tree = ast.parse((ROOT / "proxy/route_policy.py").read_text(encoding="utf-8-sig"))
        policy = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "TELEGRAM_CIDRS" for target in node.targets))
        self.assertEqual(len(policy), len(catalogue))
        self.assertEqual(set(policy), set(catalogue))
        for language in ("RU", "EN"):
            text = (ROOT / "docs" / language / "CfWorker.md").read_text(encoding="utf-8")
            self.assertIn("../../worker/telegram-worker.mjs", text)
            self.assertNotIn('import { connect }', text)

    def test_shipped_worker_with_in_memory_platform_adapters(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is needed for the Worker runtime-adapter checks")
        result = subprocess.run([node, "--test", str(ROOT / "tests/cf_worker_sample.test.mjs")],
                                cwd=ROOT, text=True, encoding="utf-8", capture_output=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
