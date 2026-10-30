import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class HelperDeployImportTest(unittest.TestCase):
    def test_helper_runs_with_the_small_proxy_subset_installed_by_deploy_script(self):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "proxy"
            package.mkdir()
            for name in ("__init__.py", "utils.py", "config.py", "balancer.py", "project.py", "http_transport.py", "route_policy.py"):
                shutil.copy2(project / "proxy" / name, package / name)
            shutil.copy2(project / "helper_server.py", root / "helper_server.py")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root)
            result = subprocess.run(
                [sys.executable, "-c", "import helper_server; assert helper_server.route_catalog()"],
                cwd=root, env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
