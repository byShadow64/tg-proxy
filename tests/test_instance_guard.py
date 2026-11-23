"""OS singleton locks use only an owned temporary app directory."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from utils import tray_common


class InstanceGuardTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.stack.enter_context(patch.object(tray_common, "APP_DIR", self.directory))
        self.stack.enter_context(patch.object(tray_common, "_instance_guard", None))
        self.stack.enter_context(patch.object(tray_common, "_lock_file_path", None))
        self.stack.enter_context(patch.object(tray_common, "IS_FROZEN", False))
        self.addCleanup(tray_common.release_lock)

    def child_acquire(self):
        code = "from pathlib import Path; import sys; from utils import tray_common as t; t.APP_DIR=Path(sys.argv[1]); print(t.acquire_lock()); t.release_lock()"
        return subprocess.check_output([sys.executable, "-B", "-c", code, str(self.directory)],
                                       cwd=Path(__file__).resolve().parents[1], text=True, timeout=10).strip()

    def test_atomic_guard_blocks_other_process_and_release_permits_restart(self):
        self.assertTrue(tray_common.acquire_lock())
        self.assertEqual(self.child_acquire(), "False")
        tray_common.release_lock()
        self.assertEqual(self.child_acquire(), "True")
        self.assertTrue((self.directory / ".instance-lock").is_file())

    def test_source_owner_is_recognized_by_interpreter_and_entrypoint(self):
        entry = self.directory / "linux.py"
        process = Mock()
        process.exe.return_value = sys.executable
        process.create_time.return_value = 123.0
        process.cwd.return_value = str(self.directory)
        process.cmdline.return_value = [sys.executable, str(entry)]
        with patch.object(sys, "argv", [str(entry)]):
            self.assertTrue(tray_common._same_process({"create_time": 123.0}, process))
            process.cmdline.return_value = [sys.executable, "unrelated.py"]
            self.assertFalse(tray_common._same_process({"create_time": 123.0}, process))

    def test_linked_guard_is_rejected_without_altering_its_target(self):
        target = self.directory / "unrelated"
        target.write_bytes(b"preserve")
        try: os.link(target, self.directory / ".instance-lock")
        except OSError as error: self.skipTest(str(error))
        self.assertFalse(tray_common.acquire_lock())
        self.assertEqual(target.read_bytes(), b"preserve")
