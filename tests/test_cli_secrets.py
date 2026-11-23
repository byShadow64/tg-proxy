"""Private-file and container argument plumbing, using synthetic values only."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from proxy import docker_entrypoint, tg_ws_proxy
from utils.cli_secrets import read_secret_file, redact_secret_arguments

SECRET = "a" * 32


class CliSecretTest(unittest.TestCase):
    def test_private_file_is_bounded_and_linked_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "secret"
            path.write_text(SECRET + "\n"); path.chmod(0o600)
            self.assertEqual(read_secret_file(path), SECRET)
            path.write_bytes(b"a" * 129)
            with self.assertRaises(ValueError): read_secret_file(path)
            path.write_text(SECRET)
            alias = path.with_name("linked")
            try: os.link(path, alias)
            except OSError: return
            with self.assertRaises(ValueError): read_secret_file(path)

    @unittest.skipIf(os.name == "nt", "POSIX private file permissions")
    def test_world_readable_secret_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "secret"
            path.write_text(SECRET); path.chmod(0o644)
            with self.assertRaises(ValueError): read_secret_file(path)

    def test_legacy_values_are_removed_from_later_python_argv(self):
        values = ["proxy", "--secret", SECRET, "--port", "1443", "--secret=" + SECRET]
        redact_secret_arguments(values)
        self.assertNotIn(SECRET, " ".join(values))
        self.assertIn("--secret=<redacted>", values)

    def test_docker_legacy_environment_never_becomes_commandline_secret(self):
        arguments = ["docker-entrypoint"]
        with patch.dict(os.environ, {"TG_WS_PROXY_SECRET": SECRET}, clear=True), \
                patch.object(sys, "argv", arguments), patch.object(tg_ws_proxy, "main") as run:
            docker_entrypoint.main()
            self.assertNotIn(SECRET, " ".join(sys.argv))
            self.assertNotIn("TG_WS_PROXY_SECRET", os.environ)
            run.assert_called_once_with(secret_override=SECRET)

    def test_docker_private_file_with_spaces_is_one_argument_and_conflicts_fail_closed(self):
        path = "/run/secrets/my proxy secret"
        with patch.dict(os.environ, {"TG_WS_PROXY_SECRET_FILE": path}, clear=True), \
                patch.object(sys, "argv", ["docker-entrypoint"]), patch.object(tg_ws_proxy, "main") as run:
            docker_entrypoint.main()
            self.assertEqual(sys.argv[sys.argv.index("--secret-file") + 1], path)
            run.assert_called_once_with(secret_override=None)
        with patch.dict(os.environ, {"TG_WS_PROXY_SECRET": SECRET, "TG_WS_PROXY_SECRET_FILE": path}, clear=True), \
                patch.object(sys, "argv", ["docker-entrypoint"]):
            with self.assertRaises(SystemExit): docker_entrypoint.main()
