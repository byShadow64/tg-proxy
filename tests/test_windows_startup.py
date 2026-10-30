"""Second launches activate the owner; background startup stays silent."""
import sys
import unittest
from contextlib import ExitStack
from unittest import mock


@unittest.skipUnless(sys.platform == "win32", "Windows startup integration")
class WindowsStartupTest(unittest.TestCase):
    def setUp(self):
        import windows
        self.app = windows
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (("_instance_activation", None), ("_exiting", False)):
            self.stack.enter_context(mock.patch.object(self.app, name, value))
        self.acquire = self.stack.enter_context(mock.patch.object(self.app, "_acquire_win_mutex"))
        self.run = self.stack.enter_context(mock.patch.object(self.app, "run_tray"))
        self.request = self.stack.enter_context(mock.patch.object(self.app, "request_activation", return_value=True))
        self.server = self.stack.enter_context(mock.patch.object(self.app, "InstanceActivation"))
        self.popup = self.stack.enter_context(mock.patch.object(self.app, "_show_info"))
        self.release = self.stack.enter_context(mock.patch.object(self.app, "_release_win_mutex"))
        self.unlock = self.stack.enter_context(mock.patch.object(self.app, "release_lock"))

    def argv(self, *args):
        self.stack.enter_context(mock.patch.object(sys, "argv", ["TgWsProxy.exe", *args]))

    def test_background_second_launch_never_activates_or_shows_dialog(self):
        self.argv("--autostart")
        self.acquire.return_value = False
        self.app.main()
        self.run.assert_not_called()
        self.request.assert_not_called()
        self.popup.assert_not_called()
        self.server.assert_not_called()
        self.release.assert_not_called()
        self.unlock.assert_not_called()

    def test_manual_second_launch_requests_existing_window_without_dialog(self):
        for args in ((), ("--dashboard",)):
            with self.subTest(args=args), mock.patch.object(sys, "argv", ["TgWsProxy.exe", *args]):
                self.acquire.return_value = False
                self.app.main()
        self.assertEqual(self.request.call_count, 2)
        self.request.assert_called_with(self.app._ACTIVATION_EVENT)
        self.popup.assert_not_called()
        self.run.assert_not_called()
        self.server.assert_not_called()

    def test_legacy_owner_without_activation_keeps_manual_fallback_only(self):
        self.argv("--dashboard")
        self.acquire.return_value = False
        self.request.return_value = False
        self.app.main()
        self.popup.assert_called_once()
        self.run.assert_not_called()

    def test_primary_creates_event_before_tray_and_cleans_it_on_failure(self):
        self.argv("--autostart")
        self.acquire.return_value = True
        order = []
        owner = self.server.return_value
        self.server.side_effect = lambda name: order.append("event") or owner
        self.run.side_effect = lambda: order.append("tray") or (_ for _ in ()).throw(RuntimeError("test"))
        with self.assertRaises(RuntimeError):
            self.app.main()
        self.assertEqual(order, ["event", "tray"])
        owner.close.assert_called_once_with()
        self.assertIsNone(self.app._instance_activation)
        self.release.assert_called_once_with()
        self.unlock.assert_called_once_with()

    def test_event_creation_failure_does_not_prevent_normal_start(self):
        self.argv()
        self.acquire.return_value = True
        self.server.side_effect = OSError("synthetic")
        with self.assertLogs(self.app.log, level="WARNING"):
            self.app.main()
        self.run.assert_called_once_with()
        self.release.assert_called_once_with()
        self.popup.assert_not_called()

    def test_primary_cleanup_keeps_mutex_release_when_event_close_fails(self):
        self.argv()
        self.acquire.return_value = True
        self.server.return_value.close.side_effect = OSError("synthetic")
        with self.assertRaises(OSError):
            self.app.main()
        self.release.assert_called_once_with()
        self.unlock.assert_called_once_with()
        self.assertIsNone(self.app._instance_activation)

    def test_real_tray_default_action_only_opens_the_existing_process(self):
        self.argv()
        icon = mock.Mock()
        with mock.patch.object(self.app, "_on_show_dashboard") as show, \
                mock.patch.object(self.app, "get_status", return_value={}), \
                mock.patch.object(self.app, "_config", {}):
            menu = self.app._build_menu()
            list(menu)[0](icon)
        show.assert_called_once()
        self.acquire.assert_not_called()
        self.run.assert_not_called()
        self.request.assert_not_called()
        self.popup.assert_not_called()

    def test_pid_lock_collision_also_activates_without_releasing_owner(self):
        self.argv("--dashboard")
        self.acquire.return_value = None
        with mock.patch.object(self.app, "acquire_lock", return_value=False):
            self.app.main()
        self.request.assert_called_once()
        self.unlock.assert_not_called()
        self.release.assert_not_called()


@unittest.skipUnless(sys.platform == "win32", "Windows autostart registry")
class AutostartMigrationTest(unittest.TestCase):
    def setUp(self):
        import windows
        self.app = windows
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(sys, "executable", r"C:\Program Files\TG Proxy.exe"))
        self.stack.enter_context(mock.patch.object(self.app, "IS_FROZEN", True))
        self.key = mock.MagicMock()
        self.stack.enter_context(mock.patch.object(self.app.winreg, "OpenKey", return_value=self.key))
        self.query = self.stack.enter_context(mock.patch.object(self.app.winreg, "QueryValueEx"))
        self.save = self.stack.enter_context(mock.patch.object(self.app.winreg, "SetValueEx"))
        self.value = f'"{sys.executable}"'

    def test_old_and_new_entries_remain_enabled_but_only_old_is_upgraded(self):
        for value, writes in ((self.value, 1), (self.value + " --autostart", 0)):
            with self.subTest(value=value):
                self.save.reset_mock()
                self.query.return_value = (value, self.app.winreg.REG_SZ)
                self.assertTrue(self.app.is_autostart_enabled())
                self.app._migrate_autostart_command()
                self.assertEqual(self.save.call_count, writes)
                if writes:
                    self.assertEqual(self.save.call_args.args[-1], self.value + " --autostart")

    def test_foreign_or_disabled_entry_is_never_enabled_or_replaced(self):
        for value in ('"C:\\Elsewhere\\TGProxy.exe"', "", self.value + " --other"):
            with self.subTest(value=value):
                self.query.return_value = (value, self.app.winreg.REG_SZ)
                self.assertFalse(self.app.is_autostart_enabled())
                self.app._migrate_autostart_command()
        self.save.assert_not_called()
        self.query.side_effect = FileNotFoundError
        self.app._migrate_autostart_command()
        self.save.assert_not_called()

    def test_source_runs_never_modify_autostart(self):
        with mock.patch.object(self.app, "IS_FROZEN", False):
            self.app._migrate_autostart_command()
        self.query.assert_not_called()
        self.save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
