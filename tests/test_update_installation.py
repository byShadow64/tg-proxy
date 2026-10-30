"""Installer protocol with real temporary files and synthetic child processes."""
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from utils import update_installer as installer


class UpdateInstallationTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.directory = Path(directory).resolve()
        self.exe = self.directory / 'Renamed proxy.exe'
        self.exe.write_bytes(b'old executable')
        self.stage = self.directory / (installer.STAGING_PREFIX + 'a' * 32)
        self.stage.mkdir()
        (self.stage / 'helper.exe').write_bytes(self.exe.read_bytes())
        (self.stage / 'payload.exe').write_bytes(b'new executable')
        self.token = 'b' * 64
        self.path = self.stage / 'plan.json'
        self.record = {
            'schema': 1, 'token': self.token, 'target': self.exe.name, 'created': time.time(),
            'old_digest': hashlib.sha256(b'old executable').hexdigest(),
            'new_digest': hashlib.sha256(b'new executable').hexdigest(), 'size': 14,
            'old_process': {'pid': 2147483647, 'created': 0},
            'arguments': ['--dashboard', '--portable'],
        }
        installer.write_json(self.path, self.record)
        self.plan = installer.load_plan(self.path, self.token)
        installer.acquire_install_lock(self.directory, self.token, self.stage)
        self.portable = self.directory / 'TgWsProxy_data'
        self.portable.mkdir()
        (self.portable / 'config.json').write_bytes(b'{"synthetic": "preserve"}')
        (self.portable / 'private-key.dat').write_bytes(b'synthetic key bytes')
        self.saved_data = {path.name: path.read_bytes() for path in self.portable.iterdir()}
        self.stack.enter_context(mock.patch.object(sys, 'executable', str(self.stage / 'helper.exe')))
        self.launches = []

        def launch(executable, arguments):
            self.launches.append((executable, arguments, executable.read_bytes()))
            process = mock.Mock(pid=os.getpid())
            process.poll.return_value = None
            return process

        self.launch = mock.Mock(side_effect=launch)
        self.ack = self.stack.enter_context(mock.patch.object(installer, '_wait_ack', return_value=True))
        self.stop = self.stack.enter_context(mock.patch.object(installer, '_stop_launched'))

    def assertDataIntact(self):
        self.assertEqual({path.name: path.read_bytes() for path in self.portable.iterdir()}, self.saved_data)

    def state(self):
        return installer._read_json(self.stage / 'state.json')

    def run_install(self, **options):
        return installer.run_update(self.path, self.token, launch=self.launch,
                                    old_timeout=.2, health_timeout=.2, **options)

    def cleanup(self):
        with mock.patch.object(installer, 'process_alive', return_value=False):
            return installer.cleanup_update(self.path, self.token, timeout=.1)

    def test_success_replaces_same_filename_requires_ack_and_removes_only_owned_files(self):
        def acknowledged(plan, attempt, process, timeout):
            self.assertEqual(self.exe.read_bytes(), b'new executable')
            self.assertEqual((self.stage / 'previous.exe').read_bytes(), b'old executable')
            self.assertEqual(self.state()['attempt'], attempt)
            return True

        self.ack.side_effect = acknowledged
        self.assertEqual(self.run_install(), 0)
        self.assertEqual(self.state()['stage'], 'complete')
        executable, arguments, content = self.launches[0]
        self.assertEqual(executable, self.exe)
        self.assertEqual(content, b'new executable')
        self.assertEqual(arguments[:2], ['--dashboard', '--portable'])
        self.assertEqual(arguments[2:], ['--update-ack', str(self.path), self.token])
        self.assertEqual(self.launches[-1][1], ['--cleanup-update', str(self.path), self.token])
        self.stop.assert_not_called()
        self.assertTrue(self.cleanup())
        self.assertFalse(self.stage.exists())
        self.assertEqual(set(self.directory.iterdir()), {self.exe, self.portable})
        self.assertDataIntact()

    def test_unacknowledged_new_process_is_stopped_then_old_executable_is_relaunched(self):
        self.ack.side_effect = [False, True]
        self.assertEqual(self.run_install(), 1)
        self.assertEqual(self.exe.read_bytes(), b'old executable')
        self.assertEqual([item[2] for item in self.launches[:2]], [b'new executable', b'old executable'])
        self.stop.assert_called_once()
        self.assertEqual(self.stop.call_args.args[2], self.exe)
        self.assertEqual(self.state()['stage'], 'rolled_back')
        self.assertTrue(self.cleanup())
        self.assertDataIntact()

    def test_new_process_launch_error_restores_and_relaunches_old(self):
        normal = self.launch.side_effect

        def launch(executable, arguments):
            if not self.launches:
                self.launches.append((executable, arguments, executable.read_bytes()))
                raise OSError('synthetic launch failure')
            return normal(executable, arguments)

        self.launch.side_effect = launch
        self.assertEqual(self.run_install(), 1)
        self.assertEqual(self.exe.read_bytes(), b'old executable')
        self.assertEqual(self.state()['stage'], 'rolled_back')
        self.assertTrue(self.cleanup())
        self.assertDataIntact()

    def test_unacknowledged_rollback_does_not_claim_success_or_delete_recovery_records(self):
        self.ack.side_effect = [False, False]
        self.assertEqual(self.run_install(), 1)
        self.assertEqual(self.exe.read_bytes(), b'old executable')
        self.assertEqual(self.state()['stage'], 'rollback_failed')
        self.assertEqual(self.state()['error'], 'TimeoutError')
        self.assertFalse(self.cleanup())
        self.assertTrue((self.stage / 'helper.exe').exists())
        self.assertTrue(self.path.exists())
        self.assertDataIntact()

    def test_partial_replace_failure_uses_backup_without_losing_the_executable(self):
        def partial(plan):
            os.replace(self.exe, self.stage / 'previous.exe')
            raise PermissionError('replacement failed after creating backup')

        with mock.patch.object(installer, '_install_payload', side_effect=partial):
            self.assertEqual(self.run_install(), 1)
        self.assertEqual(self.exe.read_bytes(), b'old executable')
        self.assertEqual(self.state()['stage'], 'rolled_back')
        self.assertTrue(self.cleanup())
        self.assertDataIntact()

    def test_failed_rollback_preserves_previous_executable_for_recovery(self):
        self.ack.return_value = False
        self.stop.side_effect = TimeoutError('child could not be stopped')
        self.assertEqual(self.run_install(), 1)
        self.assertEqual(self.state()['stage'], 'rollback_failed')
        self.assertEqual((self.stage / 'previous.exe').read_bytes(), b'old executable')
        self.assertFalse(self.cleanup())
        self.assertTrue((self.stage / 'helper.exe').exists())
        self.assertDataIntact()

    def test_payload_is_reverified_after_waiting_for_old_process(self):
        def tamper(plan, timeout):
            (self.stage / 'payload.exe').write_bytes(b'tampered executable')

        with mock.patch.object(installer, '_wait_old', side_effect=tamper), \
                mock.patch.object(installer, '_install_payload') as replace:
            self.assertEqual(self.run_install(), 1)
        replace.assert_not_called()
        self.assertEqual(self.exe.read_bytes(), b'old executable')
        self.ack.assert_not_called()
        self.assertEqual(self.state()['stage'], 'failed')
        self.assertTrue(self.cleanup())
        self.assertDataIntact()

    def test_old_process_timeout_or_cancellation_does_not_replace_or_launch_app(self):
        for error in (TimeoutError('still running'), InterruptedError('cancelled')):
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(installer, '_wait_old', side_effect=error), \
                    mock.patch.object(installer, '_install_payload') as replace:
                self.assertEqual(self.run_install(), 1)
                replace.assert_not_called()
                self.assertEqual(self.exe.read_bytes(), b'old executable')
                self.assertEqual(self.launches[-1][1][0], '--cleanup-update')
                self.ack.assert_not_called()
                # A fresh lock models a fresh preparation attempt.
                installer.acquire_install_lock(self.directory, self.token, self.stage)
        self.assertDataIntact()

    def test_bootstrap_defers_health_ack_and_removes_only_internal_arguments(self):
        self.exe.write_bytes(b'new executable')
        installer.write_json(self.stage / 'state.json', {
            'stage': 'launched', 'attempt': 'startup-attempt', 'helper': installer.process_identity(),
        })
        arguments = [str(self.exe), '--portable', '--dashboard', '--update-ack', str(self.path), self.token]
        self.assertIsNone(installer.bootstrap_dispatch(arguments))
        self.assertEqual(arguments, [str(self.exe), '--portable', '--dashboard'])
        self.assertFalse((self.stage / 'ack.json').exists())
        with mock.patch.object(sys, 'executable', str(self.exe)):
            self.assertTrue(installer.acknowledge_update())
        ack = installer._read_json(self.stage / 'ack.json')
        self.assertEqual(ack['attempt'], 'startup-attempt')
        self.assertEqual(ack['process'], installer.process_identity())
        self.assertFalse(installer.acknowledge_update())

    def test_cleanup_waits_for_helper_and_preserves_unowned_files(self):
        installer.write_json(self.stage / 'state.json', {
            'stage': 'complete', 'helper': installer.process_identity(),
        })
        self.assertFalse(installer.cleanup_update(self.path, self.token, timeout=0))
        self.assertTrue((self.stage / 'helper.exe').exists())
        unowned = self.stage / 'do-not-delete.txt'
        unowned.write_text('unowned', encoding='utf-8')
        with mock.patch.object(installer, 'process_alive', return_value=False):
            self.assertFalse(installer.cleanup_update(self.path, self.token, timeout=0))
        self.assertEqual(unowned.read_text(encoding='utf-8'), 'unowned')
        self.assertDataIntact()

    def test_paths_token_and_process_identity_cannot_redirect_installation(self):
        for target in ('../config.json', str(self.exe), 'sub\\other.exe', 'file:stream.exe'):
            with self.subTest(target=target):
                installer.write_json(self.path, {**self.record, 'target': target})
                with self.assertRaises(ValueError):
                    installer.load_plan(self.path, self.token)
        installer.write_json(self.path, self.record)
        with self.assertRaises(ValueError):
            installer.load_plan(self.path, 'c' * 64)
        actual = installer.process_identity()
        self.assertTrue(installer.process_alive(actual))
        self.assertFalse(installer.process_alive({**actual, 'created': actual['created'] - 100}))
        self.assertDataIntact()

    def test_helper_dispatch_precedes_ui_config_and_single_instance_imports(self):
        code = (
            'import sys; sys.argv=["proxy.exe","--apply-update","invalid","' + self.token + '"]; '
            '\ntry: import windows\nexcept SystemExit as e: '
            'assert e.code == 2; '
            'assert "utils.tray_common" not in sys.modules; '
            'assert "customtkinter" not in sys.modules; '
            'assert "paramiko" not in sys.modules\nelse: raise AssertionError("normal bootstrap ran")'
        )
        result = subprocess.run([sys._base_executable, '-c', code], cwd=Path(__file__).resolve().parents[1],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows file sharing semantics')
    def test_real_child_file_lock_is_gone_before_atomic_replacement(self):
        # The synthetic old process holds a Windows handle without SHARE_DELETE.
        # Its executable bytes are test data; no installed application is used.
        code = '''import ctypes,sys
k=ctypes.WinDLL('kernel32',use_last_error=True)
k.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
k.CreateFileW.restype=ctypes.c_void_p
h=k.CreateFileW(sys.argv[1],0x80000000,1,None,3,0,None)
assert h != ctypes.c_void_p(-1).value
print('locked',flush=True)
sys.stdin.readline()
k.CloseHandle(ctypes.c_void_p(h))
'''
        child = subprocess.Popen([sys._base_executable, '-c', code, str(self.exe)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        self.assertEqual(child.stdout.readline().strip(), 'locked')
        self.record['old_process'] = installer.process_identity(child.pid)
        installer.write_json(self.path, self.record)
        result = []
        worker = threading.Thread(target=lambda: result.append(installer.run_update(
            self.path, self.token, launch=self.launch, old_timeout=5, health_timeout=.2)))
        worker.start()
        try:
            deadline = time.monotonic() + 3
            while not (self.stage / 'state.json').exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertEqual(self.state()['stage'], 'ready')
            self.assertEqual(self.exe.read_bytes(), b'old executable')
            self.launch.assert_not_called()
            child.stdin.write('exit\n')
            child.stdin.flush()
            child.wait(timeout=3)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
            worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [0])
        self.assertEqual(self.exe.read_bytes(), b'new executable')
        self.assertTrue(self.cleanup())
        self.assertDataIntact()


class UpdateLaunchEnvironmentTest(unittest.TestCase):
    def test_each_helper_and_application_gets_a_fresh_frozen_bundle(self):
        dll = mock.Mock()
        with mock.patch.object(sys, '_MEIPASS', 'old-bundle', create=True), \
                mock.patch.object(installer.ctypes, 'windll', dll, create=True), \
                mock.patch.object(installer.subprocess, 'Popen') as launch:
            installer.launch_executable(Path('C:/private/proxy.exe'), ['--dashboard'])
        self.assertEqual(launch.call_args.kwargs['env']['PYINSTALLER_RESET_ENVIRONMENT'], '1')
        self.assertEqual(launch.call_args.kwargs['cwd'], str(Path('C:/private')))
        if sys.platform == 'win32':
            calls = dll.kernel32.SetDllDirectoryW.call_args_list
            self.assertEqual(calls[0], mock.call(None))
            self.assertEqual(calls[1].args[0].value, 'old-bundle')


if __name__ == '__main__':
    unittest.main()
