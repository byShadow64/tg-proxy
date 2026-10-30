"""Real updater handoff may temporarily lock the file being observed."""
import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    'verify_update_chain', Path(__file__).resolve().parents[1] / 'packaging' / 'verify_update_chain.py')
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


class UpdateChainVerificationTest(unittest.TestCase):
    def test_cleanup_stops_installer_first_and_rescans_for_restarted_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            stopped = []

            def process(name, folder, args=()):
                item = mock.Mock()
                item.info = {'exe': str(folder / name), 'cmdline': list(args)}
                item.cmdline.return_value = list(args)
                item.terminate.side_effect = lambda: stopped.append(name)
                return item

            app = process('old.exe', root)
            helper = process('helper.exe', root, ('--apply-update',))
            replacement = process('new.exe', root)
            unrelated = process('unrelated.exe', root.parent)
            snapshots = [[app, helper, unrelated], [replacement, unrelated],
                         [unrelated], [unrelated], [unrelated]]
            with mock.patch.object(verification.psutil, 'process_iter', side_effect=snapshots), \
                    mock.patch.object(verification.psutil, 'wait_procs', side_effect=lambda items, timeout: (items, [])), \
                    mock.patch.object(verification.time, 'sleep'):
                verification.stop_owned(root)
            self.assertEqual(stopped, ['helper.exe', 'old.exe', 'new.exe'])
            unrelated.terminate.assert_not_called()

    @unittest.skipUnless(os.name == 'nt', 'Windows file-sharing semantics')
    def test_locked_executable_is_pending_and_becomes_verifiable_when_released(self):
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'application.exe'
            path.write_bytes(b'new verified application')
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)
            self.assertNotEqual(handle, wintypes.HANDLE(-1).value)
            try:
                self.assertFalse(verification.installed_digest_matches(path, expected))
            finally:
                kernel.CloseHandle(handle)
            self.assertTrue(verification.installed_digest_matches(path, expected))
            self.assertFalse(verification.installed_digest_matches(path, '0' * 64))
            path.unlink()
            self.assertFalse(verification.installed_digest_matches(path, expected))
