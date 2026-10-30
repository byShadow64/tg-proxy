import sys
import threading
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock
from tkinter import TclError


class DashboardWindow:
    def __init__(self):
        self.destroyed = False

    def winfo_exists(self):
        return not self.destroyed

    def destroy(self):
        self.destroyed = True

    def deiconify(self):
        pass

    def lift(self):
        pass

    def focus_force(self):
        pass


class ImmediateThread:
    def __init__(self, *, target, **kwargs):
        self.target = target

    def start(self):
        self.target()


@unittest.skipUnless(sys.platform == "win32", "Windows tray integration")
class DashboardRecoveryTest(unittest.TestCase):
    def test_recovered_tk_root_replaces_stale_dashboard_reference(self):
        import windows as app

        old, new, view = DashboardWindow(), DashboardWindow(), mock.Mock()
        old.winfo_exists = mock.Mock(side_effect=TclError("Synthetic closed interpreter"))
        events = []

        def run_dialog(build):
            done = threading.Event()
            events.append(done)
            build(done)

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(app, "_dashboard_window", old))
            stack.enter_context(mock.patch.object(app, "_dashboard_view", mock.Mock()))
            stack.enter_context(mock.patch.object(app, "_dashboard_opening", False))
            stack.enter_context(mock.patch.object(app.threading, "Thread", ImmediateThread))
            stack.enter_context(mock.patch.object(app, "ensure_ctk_thread", return_value=True))
            stack.enter_context(mock.patch.object(app, "ctk_run_dialog", side_effect=run_dialog))
            stack.enter_context(mock.patch.object(app, "ctk", SimpleNamespace(CTkToplevel=mock.Mock(return_value=new))))
            stack.enter_context(mock.patch.object(app, "install_window_icon"))
            stack.enter_context(mock.patch.object(app, "build_dashboard", return_value=view))
            app._on_show_dashboard()
            self.assertIs(app._dashboard_window, new)
            self.assertIs(app._dashboard_view, view)
            self.assertFalse(events[0].is_set())

    def test_nested_tk_events_during_construction_coalesce_open_requests(self):
        import windows as app

        root, view = DashboardWindow(), mock.Mock()
        events = []

        def run_dialog(build):
            done = threading.Event()
            events.append(done)
            build(done)

        builds = []

        def build_dashboard(*args, **kwargs):
            builds.append(True)
            if len(builds) == 1:
                # CTk geometry/font operations may pump nested Tk events.
                app._on_show_dashboard()
                app._on_show_dashboard(show_logs=True)
            return view

        with ExitStack() as stack:
            for name in ("_dashboard_window", "_dashboard_view"):
                stack.enter_context(mock.patch.object(app, name, None))
            stack.enter_context(mock.patch.object(app.threading, "Thread", ImmediateThread))
            stack.enter_context(mock.patch.object(app, "ensure_ctk_thread", return_value=True))
            stack.enter_context(mock.patch.object(app, "ctk_run_dialog", side_effect=run_dialog))
            factory = mock.Mock(return_value=root)
            stack.enter_context(mock.patch.object(app, "ctk", SimpleNamespace(CTkToplevel=factory)))
            stack.enter_context(mock.patch.object(app, "install_window_icon"))
            error = stack.enter_context(mock.patch.object(app, "_show_error"))
            stack.enter_context(mock.patch.object(app, "build_dashboard", side_effect=build_dashboard))
            app._on_show_dashboard()
            self.assertEqual(len(builds), 1)
            factory.assert_called_once_with()
            self.assertTrue(events[1].is_set())
            self.assertTrue(events[2].is_set())
            self.assertFalse(events[0].is_set())
            view.show_logs.assert_called_once_with()
            error.assert_not_called()

    def test_failed_construction_closes_partial_window_and_next_attempt_succeeds(self):
        import windows as app

        first, second = DashboardWindow(), DashboardWindow()
        done_events = []
        view = mock.Mock()

        def run_dialog(build):
            done = threading.Event()
            done_events.append(done)
            build(done)

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(app, "_dashboard_window", None))
            stack.enter_context(mock.patch.object(app, "_dashboard_view", None))
            stack.enter_context(mock.patch.object(app.threading, "Thread", ImmediateThread))
            stack.enter_context(mock.patch.object(app, "ensure_ctk_thread", return_value=True))
            stack.enter_context(mock.patch.object(app, "ctk_run_dialog", side_effect=run_dialog))
            stack.enter_context(mock.patch.object(app, "ctk", SimpleNamespace(
                CTkToplevel=mock.Mock(side_effect=[first, second]),
            )))
            stack.enter_context(mock.patch.object(app, "install_window_icon"))
            error = stack.enter_context(mock.patch.object(app, "_show_error"))
            build = stack.enter_context(mock.patch.object(
                app, "build_dashboard", side_effect=[ImportError("PIL._imagingtk"), view],
            ))
            with self.assertLogs(app.log, level="ERROR"):
                app._on_show_dashboard()
            self.assertTrue(first.destroyed)
            self.assertIsNone(app._dashboard_window)
            self.assertIsNone(app._dashboard_view)
            self.assertTrue(done_events[0].is_set())
            error.assert_called_once()

            app._on_show_dashboard(show_logs=True)
            self.assertFalse(second.destroyed)
            self.assertIs(app._dashboard_window, second)
            self.assertIs(app._dashboard_view, view)
            self.assertFalse(done_events[1].is_set())
            view.show_logs.assert_called_once_with()
            build.call_args.kwargs["on_close"]()
            self.assertTrue(done_events[1].is_set())
            self.assertIsNone(app._dashboard_window)
            self.assertIsNone(app._dashboard_view)

    def test_dashboard_flag_opens_window_before_tray_event_loop(self):
        import windows as app

        for enabled in (True, False):
            with self.subTest(enabled=enabled), ExitStack() as stack:
                icon = mock.Mock()
                manager = mock.Mock()
                show = stack.enter_context(mock.patch.object(app, "_on_show_dashboard"))
                manager.attach_mock(show, "show")
                manager.attach_mock(icon.run, "run")
                stack.enter_context(mock.patch.object(app.sys, "argv", ["TGProxy.exe"] + (["--dashboard"] if enabled else [])))
                stack.enter_context(mock.patch.object(app, "pystray", SimpleNamespace(Icon=mock.Mock(return_value=icon))))
                stack.enter_context(mock.patch.object(app, "ctk", object()))
                stack.enter_context(mock.patch.object(app, "Image", object()))
                stack.enter_context(mock.patch.object(app, "_config", {}))
                stack.enter_context(mock.patch.object(app, "_tray_icon", None))
                stack.enter_context(mock.patch.object(app, "load_config", return_value={}))
                acknowledge = stack.enter_context(mock.patch.object(app, "acknowledge_update"))
                stack.enter_context(mock.patch.object(app, "is_windows_dark_theme", return_value=False))
                for name in ("bootstrap", "start_proxy", "check_update_async", "_show_first_run",
                             "check_ipv6_warning", "load_icon", "_build_menu", "stop_proxy"):
                    stack.enter_context(mock.patch.object(app, name))
                app.run_tray()
                expected = [mock.call.show(), mock.call.run(setup=mock.ANY)] if enabled else [mock.call.run(setup=mock.ANY)]
                self.assertEqual(manager.mock_calls, expected)
                acknowledge.assert_not_called()
                icon.run.call_args.kwargs["setup"](icon)
                self.assertTrue(icon.visible)
                acknowledge.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
