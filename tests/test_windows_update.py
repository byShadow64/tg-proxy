import hashlib
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from utils import update_installer, windows_update


class AssetNameTest(unittest.TestCase):
    def test_keeps_the_running_build_even_when_renamed_or_emulated(self):
        builds = (
            ('win-amd64', (3, 11), 'TgWsProxy_windows.exe'),
            ('win-amd64', (3, 8), 'TgWsProxy_windows_7_64bit.exe'),
            ('win32', (3, 8), 'TgWsProxy_windows_7_32bit.exe'),
            ('win-arm64', (3, 11), 'TgWsProxy_windows_arm64.exe'),
            ('unknown', (3, 11), None),
        )
        for platform, version, expected in builds:
            with self.subTest(platform=platform, version=version), \
                    mock.patch.object(windows_update.sysconfig, 'get_platform', return_value=platform), \
                    mock.patch.object(sys, 'version_info', version), \
                    mock.patch.object(sys, 'executable', 'renamed.exe'):
                self.assertEqual(windows_update.asset_name(), expected)


class HelperReadinessTest(unittest.TestCase):
    def test_first_state_can_arrive_after_helper_extraction_started(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            missing_observed = threading.Event()
            process = mock.Mock()
            process.poll.side_effect = lambda: missing_observed.set() or None

            def helper():
                if missing_observed.wait(2):
                    update_installer.write_json(stage / 'state.json', {
                        'stage': 'ready', 'helper': update_installer.process_identity(),
                    })

            worker = threading.Thread(target=helper)
            worker.start()
            try:
                self.assertFalse((stage / 'state.json').exists())
                windows_update._wait_ready(stage, process, timeout=2)
                self.assertTrue(missing_observed.is_set())
                self.assertEqual(update_installer._read_json(stage / 'state.json')['stage'], 'ready')
            finally:
                missing_observed.set()
                worker.join(timeout=3)
            self.assertFalse(worker.is_alive())

    def test_corrupt_or_invalid_state_is_not_treated_as_extraction_delay(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            process = mock.Mock()
            for contents in ('{incomplete', '[]'):
                with self.subTest(contents=contents):
                    (stage / 'state.json').write_text(contents, encoding='utf-8')
                    with self.assertRaises(ValueError):
                        windows_update._wait_ready(stage, process, timeout=2)
                    process.poll.assert_not_called()


class ApplyUpdateTest(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(windows_update.update_progress, '_state', {
            'active': False, 'phase': 'idle', 'downloaded': 0, 'total': None, 'version': '',
        }))
        directory = stack.enter_context(tempfile.TemporaryDirectory())
        self.exe = Path(directory) / 'renamed app.exe'
        self.exe.write_bytes(b'old')
        self.asset = {'url': 'https://example.invalid/new.exe',
                      'digest': 'sha256:' + hashlib.sha256(b'new').hexdigest()}
        stack.enter_context(mock.patch.object(sys, 'executable', str(self.exe)))
        stack.enter_context(mock.patch.object(sys, 'argv', [str(self.exe), '--portable']))
        stack.enter_context(mock.patch.object(sys, '_MEIPASS', None, create=True))
        stack.enter_context(mock.patch.object(sys, 'frozen', True, create=True))
        self.download = stack.enter_context(mock.patch.object(
            windows_update, 'download_release_asset', side_effect=self.download_file))
        self.launch = stack.enter_context(mock.patch.object(update_installer, 'launch_executable'))
        self.launch.return_value.poll.return_value = None
        self.ready = stack.enter_context(mock.patch.object(windows_update, '_wait_ready', side_effect=self.helper_ready))
        self.prepare = mock.Mock()
        self.stage = None

    def download_file(self, asset, directory, **kwargs):
        downloaded = directory / 'download.exe'
        downloaded.write_bytes(b'new')
        return downloaded, asset

    def helper_ready(self, stage, process):
        self.stage = stage
        self.assertEqual(self.exe.read_bytes(), b'old')
        update_installer.write_json(stage / 'state.json', {
            'stage': 'ready', 'helper': {'pid': 2147483647, 'created': 0},
        })

    def test_verified_update_hands_off_without_changing_the_live_executable(self):
        def prepare():
            self.assertEqual(self.exe.read_bytes(), b'old')
            self.assertEqual((self.stage / 'payload.exe').read_bytes(), b'new')
            self.assertEqual((self.stage / 'helper.exe').read_bytes(), b'old')
            self.launch.assert_called_once()

        windows_update.apply_update(self.asset, prepare)
        self.assertEqual(self.exe.read_bytes(), b'old')
        executable, arguments = self.launch.call_args.args
        self.assertEqual(executable, self.stage / 'helper.exe')
        self.assertEqual(arguments[0], '--apply-update')
        plan = update_installer.load_plan(arguments[1], arguments[2])
        self.assertEqual(plan['target'], self.exe.name)
        self.assertEqual(plan['arguments'], ['--portable'])
        self.assertEqual(plan['new_digest'], hashlib.sha256(b'new').hexdigest())
        self.assertEqual(plan['old_process'], update_installer.process_identity())
        self.assertFalse(self.exe.with_name('renamed app_oldtgws.exe').exists())

    def test_missing_or_corrupt_checksum_does_not_replace_or_launch(self):
        for digest in ('', 'sha256:' + '0' * 64):
            with self.subTest(digest=digest):
                self.asset['digest'] = digest
                with self.assertRaises((OSError, ValueError)):
                    windows_update.apply_update(self.asset, self.prepare)
                self.assertEqual(self.exe.read_bytes(), b'old')
                self.assertEqual(list(self.exe.parent.iterdir()), [self.exe])
                self.prepare.assert_not_called()
                self.launch.assert_not_called()

    def test_helper_launch_failure_keeps_the_live_executable_and_cleans_staging(self):
        self.launch.side_effect = OSError('launch failed')
        with self.assertRaisesRegex(OSError, 'launch failed'):
            windows_update.apply_update(self.asset, self.prepare)
        self.prepare.assert_not_called()
        self.assertEqual(self.exe.read_bytes(), b'old')
        self.assertEqual(list(self.exe.parent.iterdir()), [self.exe])

    def test_unwritable_install_directory_does_not_stop_the_application(self):
        with mock.patch.object(windows_update.tempfile, 'mkdtemp', side_effect=PermissionError('read only')):
            with self.assertRaises(PermissionError):
                windows_update.apply_update(self.asset, self.prepare)
        self.assertEqual(self.exe.read_bytes(), b'old')
        self.assertEqual(list(self.exe.parent.iterdir()), [self.exe])
        self.prepare.assert_not_called()
        self.launch.assert_not_called()
        self.download.assert_not_called()

    def test_preparation_callback_failure_cancels_helper_before_replacement(self):
        self.prepare.side_effect = OSError('stop failed')
        with self.assertRaisesRegex(OSError, 'stop failed'):
            windows_update.apply_update(self.asset, self.prepare)
        self.assertEqual(self.exe.read_bytes(), b'old')
        self.assertEqual(list(self.exe.parent.iterdir()), [self.exe])
        self.launch.return_value.wait.assert_called_once_with(timeout=15)

    def test_parallel_or_pending_installation_cannot_download_again(self):
        windows_update._prepare_lock.acquire()
        try:
            with self.assertRaises(update_installer.UpdateBusyError):
                windows_update.apply_update(self.asset, self.prepare)
            self.download.assert_not_called()
        finally:
            windows_update._prepare_lock.release()
        windows_update.apply_update(self.asset, self.prepare)
        with self.assertRaises(update_installer.UpdateBusyError):
            windows_update.apply_update(self.asset, self.prepare)
        self.download.assert_called_once()
        self.prepare.assert_called_once_with()
        self.assertEqual(self.exe.read_bytes(), b'old')

    def test_progress_phases_follow_verified_download_and_real_helper_readiness(self):
        self.asset.update(version='1.14.8', size=3)
        observed = []
        def phase():
            observed.append(windows_update.update_progress.get_progress()['phase'])
        def streamed(asset, directory, **callbacks):
            phase()
            callbacks['on_candidate'](asset)
            phase()
            callbacks['progress'](3, 3)
            callbacks['on_verifying']()
            phase()
            return self.download_file(asset, directory)
        self.download.side_effect = streamed
        process = self.launch.return_value
        self.launch.side_effect = lambda *arguments: phase() or process
        real_ready = self.ready.side_effect
        self.ready.side_effect = lambda *arguments: phase() or real_ready(*arguments)
        windows_update.apply_update(self.asset, phase)
        self.assertEqual(observed, ['preparing', 'downloading', 'verifying',
            'starting_installer', 'starting_installer', 'restarting'])
        progress = windows_update.update_progress.get_progress()
        self.assertEqual(progress, {'active': True, 'phase': 'restarting', 'downloaded': 3,
            'total': 3, 'version': '1.14.8'})
        self.assertNotIn('installed', progress.values())

    def test_duplicate_preserves_current_progress_even_while_waiting_for_handoff(self):
        progress = windows_update.update_progress
        run = progress.begin('1.14.8')
        progress.start_download(run, '1.14.8', 100)
        progress.set_download(run, 35, 100)
        before = progress.get_progress()
        with self.assertRaises(update_installer.UpdateBusyError):
            windows_update.apply_update(self.asset, self.prepare)
        self.assertEqual(progress.get_progress(), before)
        self.download.assert_not_called()

    def test_failure_publishes_only_generic_failed_state_and_retry_gets_new_generation(self):
        self.asset['version'] = '1.14.8'
        self.download.side_effect = OSError('PRIVATE https://private.invalid/password')
        with self.assertRaises(OSError):
            windows_update.apply_update(self.asset, self.prepare)
        progress = windows_update.update_progress.get_progress()
        self.assertFalse(progress['active'])
        self.assertEqual(progress['phase'], 'failed')
        self.assertNotIn('PRIVATE', repr(progress))
        self.assertNotIn('private.invalid', repr(progress))
        self.download.side_effect = self.download_file
        windows_update.apply_update(self.asset, self.prepare)
        self.assertEqual(windows_update.update_progress.get_progress()['phase'], 'restarting')

    def test_failed_state_is_deferred_until_blocked_cleanup_finishes(self):
        entered, release = threading.Event(), threading.Event()
        callbacks, errors = [], []
        real_cleanup = windows_update._cancel_and_clean
        self.asset.update(version='1.14.8', size=3)

        def interrupted(asset, directory, **hooks):
            callbacks.append(hooks)
            hooks['on_candidate'](asset)
            hooks['progress'](2, 3)
            raise OSError('interrupted stream')

        def blocked_cleanup(*arguments):
            entered.set()
            if not release.wait(2):
                raise TimeoutError('test did not release cleanup')
            return real_cleanup(*arguments)

        def run():
            try:
                windows_update.apply_update(self.asset, self.prepare)
            except Exception as exc:
                errors.append(exc)

        self.download.side_effect = interrupted
        with mock.patch.object(windows_update, '_cancel_and_clean', side_effect=blocked_cleanup):
            worker = threading.Thread(target=run)
            worker.start()
            try:
                self.assertTrue(entered.wait(1))
                during = windows_update.update_progress.get_progress()
                self.assertTrue(during['active'])
                self.assertEqual(during['phase'], 'downloading')
                self.assertEqual(during['downloaded'], 2)
                with self.assertRaises(update_installer.UpdateBusyError):
                    windows_update.apply_update(self.asset, self.prepare)
                self.assertEqual(self.download.call_count, 1)
                self.assertEqual(windows_update.update_progress.get_progress(), during)
            finally:
                release.set()
                worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertEqual(str(errors[0]), 'interrupted stream')
        after = windows_update.update_progress.get_progress()
        self.assertFalse(after['active'])
        self.assertEqual(after['phase'], 'failed')
        callbacks[0]['progress'](3, 3)
        callbacks[0]['on_verifying']()
        callbacks[0]['on_candidate']({**self.asset, 'version': '1.14.9'})
        self.assertEqual(windows_update.update_progress.get_progress(), after)
        self.assertEqual(list(self.exe.parent.iterdir()), [self.exe])

    def test_cleanup_exception_still_marks_progress_failed(self):
        self.download.side_effect = OSError('download interrupted')
        with mock.patch.object(windows_update, '_cancel_and_clean', side_effect=RuntimeError('cleanup failed')):
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                windows_update.apply_update(self.asset, self.prepare)
        self.assertFalse(windows_update.update_progress.get_progress()['active'])
        self.assertEqual(windows_update.update_progress.get_progress()['phase'], 'failed')

    def test_fallback_payload_is_reverified_using_its_actual_asset(self):
        actual = {**self.asset, 'digest': 'sha256:' + hashlib.sha256(b'fallback').hexdigest(), 'size': 8}

        def fallback(asset, directory, **kwargs):
            path = directory / 'download.exe'
            path.write_bytes(b'fallback')
            return path, actual

        self.download.side_effect = fallback
        windows_update.apply_update(self.asset, self.prepare)
        self.assertEqual((self.stage / 'payload.exe').read_bytes(), b'fallback')

    def test_source_checkout_is_never_replaced(self):
        with mock.patch.object(sys, 'frozen', False):
            with self.assertRaisesRegex(ValueError, 'packaged'):
                windows_update.apply_update(self.asset, self.prepare)
        self.download.assert_not_called()
        self.prepare.assert_not_called()
        self.assertEqual(list(self.exe.parent.iterdir()), [self.exe])

    def test_helper_not_ready_does_not_stop_the_application(self):
        self.ready.side_effect = TimeoutError('helper not ready')
        with self.assertRaises(TimeoutError):
            windows_update.apply_update(self.asset, self.prepare)
        self.prepare.assert_not_called()
        self.assertEqual(self.exe.read_bytes(), b'old')
        self.assertEqual(list(self.exe.parent.iterdir()), [self.exe])


@unittest.skipUnless(sys.platform == 'win32', 'Windows tray integration')
class UpdateFlowTest(unittest.TestCase):
    def setUp(self):
        import windows

        self.windows = windows

    def test_fallback_dialog_actually_installs_the_selected_asset(self):
        app = self.windows
        asset = {'url': 'https://example.invalid/new.exe', 'digest': 'sha256:' + '0' * 64}
        with mock.patch.object(app, 'ctk', None), \
                mock.patch.object(app._u32, 'MessageBoxW', return_value=app._IDYES), \
                mock.patch.object(app, '_perform_update') as update:
            app.update_ctk_form('update', asset=asset)
        update.assert_called_once_with(asset)

    def test_failed_launch_recovers_proxy_and_lock_instead_of_exiting(self):
        app = self.windows

        def fail(asset, before_restart):
            before_restart()
            raise OSError('launch failed')

        with ExitStack() as stack:
            mocks = {name: stack.enter_context(mock.patch.object(app, name)) for name in (
                'apply_update', 'stop_proxy', 'release_lock', '_release_win_mutex',
                '_acquire_win_mutex', 'acquire_lock', 'start_proxy', '_show_error',
            )}
            exit_process = stack.enter_context(mock.patch.object(app.os, '_exit'))
            mocks['apply_update'].side_effect = fail
            mocks['_acquire_win_mutex'].return_value = None
            app._perform_update({'url': 'asset', 'digest': 'digest'})
        mocks['stop_proxy'].assert_called_once_with()
        mocks['release_lock'].assert_called_once_with()
        mocks['_release_win_mutex'].assert_called_once_with()
        mocks['acquire_lock'].assert_called_once_with()
        mocks['start_proxy'].assert_called_once_with(app._config, mocks['_show_error'])
        mocks['_show_error'].assert_called_once()
        exit_process.assert_not_called()

    def test_download_failure_leaves_proxy_and_locks_running(self):
        app = self.windows
        with mock.patch.object(app, 'apply_update', side_effect=OSError('checksum mismatch')), \
                mock.patch.object(app, 'stop_proxy') as stop, \
                mock.patch.object(app, 'release_lock') as unlock, \
                mock.patch.object(app, '_show_error'), \
                mock.patch.object(app.os, '_exit') as exit_process:
            app._perform_update({})
        stop.assert_not_called()
        unlock.assert_not_called()
        exit_process.assert_not_called()

    def test_automatic_flow_installs_verified_asset_without_prompt_or_browser(self):
        app = self.windows
        asset = {'url': 'https://example.invalid/new.exe', 'digest': 'sha256:' + '0' * 64}
        finished = threading.Event()
        caller = threading.get_ident()
        worker = []

        def perform(selected):
            self.assertEqual(selected, asset)
            worker.append(threading.get_ident())
            finished.set()

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(app, '_update_flow_lock', threading.Lock()))
            stack.enter_context(mock.patch.object(app, '_exiting', False))
            stack.enter_context(mock.patch.object(app, '_tray_icon', None))
            stack.enter_context(mock.patch.object(app, 'IS_FROZEN', True))
            stack.enter_context(mock.patch.object(app, 'get_status', return_value={'has_update': True, 'latest': '99.0.0'}))
            stack.enter_context(mock.patch.object(app, 'find_asset', return_value=asset))
            perform_mock = stack.enter_context(mock.patch.object(app, '_perform_update', side_effect=perform))
            prompt = stack.enter_context(mock.patch.object(app, 'update_ctk_form'))
            browser = stack.enter_context(mock.patch.object(app.webbrowser, 'open'))
            app._trigger_update_flow(automatic=True)
            self.assertTrue(finished.wait(3))
            self.assertTrue(app._update_flow_lock.acquire(timeout=3))
            app._update_flow_lock.release()
            perform_mock.assert_called_once_with(asset)
            self.assertNotEqual(worker, [caller])
            prompt.assert_not_called()
            browser.assert_not_called()

    def test_automatic_flow_without_matching_verified_asset_does_not_prompt(self):
        app = self.windows
        finished = threading.Event()

        def no_asset(name):
            finished.set()
            return None

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(app, '_update_flow_lock', threading.Lock()))
            stack.enter_context(mock.patch.object(app, '_exiting', False))
            stack.enter_context(mock.patch.object(app, '_tray_icon', None))
            stack.enter_context(mock.patch.object(app, 'IS_FROZEN', True))
            stack.enter_context(mock.patch.object(app, 'get_status', return_value={'has_update': True}))
            stack.enter_context(mock.patch.object(app, 'find_asset', side_effect=no_asset))
            perform = stack.enter_context(mock.patch.object(app, '_perform_update'))
            prompt = stack.enter_context(mock.patch.object(app, 'update_ctk_form'))
            app._trigger_update_flow(automatic=True)
            self.assertTrue(finished.wait(3))
            self.assertTrue(app._update_flow_lock.acquire(timeout=3))
            app._update_flow_lock.release()
            perform.assert_not_called()
            prompt.assert_not_called()
