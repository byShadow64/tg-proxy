"""Native dashboard stop controls with an in-memory proxy lifecycle."""
import subprocess
import sys
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from tkinter import TclError

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ui.ctk_theme import apply_ctk_appearance, ctk_theme_for_platform
from ui.dashboard import build_dashboard
from ui.i18n import get_config_language, set_language, t
from utils import update_check
from utils.live_logs import LiveLogHandler

_NATIVE_MODE = "--native-run" in sys.argv
_OMITTED = object()


if not _NATIVE_MODE:
    class DashboardStopProcessTest(unittest.TestCase):
        def test_native_dashboard_stop_scenarios(self):
            # Native UI suites use separate processes because CTk caches fonts
            # and images against the first Tcl interpreter in each process.
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--native-run"],
                capture_output=True, text=True, timeout=35,
            )
            if "NATIVE_DISPLAY_UNAVAILABLE" in result.stdout:
                self.skipTest("Native Tk display is unavailable")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if _NATIVE_MODE:
    class NativeDashboardStopTest(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            import customtkinter as ctk

            cls.ctk = ctk
            try:
                cls.app = ctk.CTk()
            except TclError as exc:
                print("NATIVE_DISPLAY_UNAVAILABLE")
                raise unittest.SkipTest(str(exc)) from exc
            cls.app.withdraw()

        @classmethod
        def tearDownClass(cls):
            if hasattr(cls, "app"):
                cls.app.destroy()

        def setUp(self):
            self.views, self.errors = [], []
            self.app.report_callback_exception = lambda *args: self.errors.append(args)
            self.addCleanup(set_language, get_config_language())
            self.addCleanup(self.ctk.set_appearance_mode, self.ctk.get_appearance_mode())
            set_language("en")
            apply_ctk_appearance(self.ctk, "light")
            self.theme = ctk_theme_for_platform()
            self.stack = ExitStack()
            self.addCleanup(self.stack.close)
            self.network = self.stack.enter_context(mock.patch.object(
                update_check, "fetch_latest_release", side_effect=AssertionError("Real network is forbidden"),
            ))

        def tearDown(self):
            for view in self.views:
                if not view.closed:
                    view.close()
            self.app.update()
            self.network.assert_not_called()
            self.assertFalse(self.errors)

        def pump(self, milliseconds=20):
            ready = self.ctk.BooleanVar(master=self.app, value=False)
            self.app.after(milliseconds, lambda: ready.set(True))
            self.app.wait_variable(ready)
            self.app.update()

        def until(self, predicate, timeout=3):
            deadline = time.monotonic() + timeout
            while not predicate():
                if time.monotonic() >= deadline:
                    self.fail("Dashboard did not reach the expected stop state")
                self.pump()
            self.app.update_idletasks()

        def view(self, state, *, on_stop=_OMITTED):
            root = self.ctk.CTkToplevel(self.app)
            root.withdraw()
            restart = mock.Mock(side_effect=lambda: state.update(alive=True))
            telegram, closed = mock.Mock(), mock.Mock()
            options = {} if on_stop is _OMITTED else {"on_stop": on_stop}
            view = build_dashboard(
                self.ctk, root, self.theme,
                {"host": "127.0.0.1", "port": 1443, "helper_enabled": False},
                running=lambda: state["alive"], on_telegram=telegram,
                on_settings=lambda: None, on_restart=restart,
                on_close=closed, config_path="synthetic-config.json",
                log_source=LiveLogHandler(), **options,
            )
            self.views.append(view)
            root.geometry("860x640+12000+12000")
            root.deiconify()
            self.wait_layout(view)
            return view, restart, telegram, closed

        def wait_layout(self, view, *, size=(860, 640), timeout=3):
            # A fixed 80 ms tick is not a mapping barrier when other native
            # processes/UIA clients are busy. Wait for observable layout, then
            # keep all mapping and containment assertions in the tests below.
            deadline = time.monotonic() + timeout
            canvas = view.overview._parent_canvas
            while not (view.root.winfo_ismapped() and view.updates.frame.winfo_ismapped()
                       and view.root.winfo_width() == round(size[0] * view.root._get_window_scaling())
                       and view.root.winfo_height() == round(size[1] * view.root._get_window_scaling())
                       and view.updates.frame.winfo_width() > 1
                       and view.updates.frame.winfo_height() > 1
                       and canvas.winfo_width() > 1 and canvas.winfo_height() > 1
                       and abs(view.overview.winfo_width() - canvas.winfo_width()) <= 1):
                if time.monotonic() >= deadline:
                    self.fail("Dashboard layout did not become ready; footer=" +
                              self.layout_details(view.updates.frame) + "; canvas=" +
                              self.layout_details(canvas))
                self.pump()
            self.app.update_idletasks()

        def assertInside(self, widget, container):
            if not widget.winfo_ismapped():
                self.fail("Widget is not mapped: " + self.layout_details(widget))
            x = widget.winfo_rootx() - container.winfo_rootx()
            y = widget.winfo_rooty() - container.winfo_rooty()
            self.assertGreaterEqual(x, -1)
            self.assertGreaterEqual(y, -1)
            self.assertLessEqual(x + widget.winfo_width(), container.winfo_width() + 1)
            self.assertLessEqual(y + widget.winfo_height(), container.winfo_height() + 1)

        @staticmethod
        def layout_details(widget):
            details = []
            while widget is not None:
                details.append({
                    "widget": str(widget), "mapped": bool(widget.winfo_ismapped()),
                    "manager": widget.winfo_manager(),
                    "geometry": widget.winfo_geometry(),
                    "requested": (widget.winfo_reqwidth(), widget.winfo_reqheight()),
                })
                widget = getattr(widget, "master", None)
            return repr(details)

        def test_stop_is_async_rejects_duplicates_and_switches_to_start_after_success(self):
            state = {"alive": True}
            entered, release = threading.Event(), threading.Event()
            worker_ids = []

            def stop():
                worker_ids.append(threading.get_ident())
                entered.set()
                if release.wait(3):
                    state["alive"] = False

            callback = mock.Mock(side_effect=stop)
            view, restart, telegram, _ = self.view(state, on_stop=callback)
            try:
                view.stop_button.invoke()
                self.assertTrue(entered.wait(2))
                self.assertNotEqual(worker_ids, [threading.get_ident()])
                self.assertTrue(view._stopping)
                self.assertEqual(view.stop_button.cget("state"), "disabled")
                self.assertEqual(view.stop_button.cget("text"), t("dashboard.stopping"))
                self.assertEqual(view.telegram_button.cget("state"), "disabled")
                self.assertEqual(view.restart_button.cget("state"), "disabled")
                view.stop_button.invoke()
                view.stop_proxy()
                view.telegram_button.invoke()
                view.restart_button.invoke()
                heartbeat = []
                self.app.after(0, lambda: heartbeat.append(True))
                self.pump(60)
                self.assertEqual(heartbeat, [True])
                callback.assert_called_once_with()
                restart.assert_not_called()
                telegram.assert_not_called()
                set_language("ru")
                view.refresh()
                self.assertEqual(view.stop_button.cget("text"), t("dashboard.stopping"))
                self.assertEqual(view.status.cget("text"), t("dashboard.stopping"))
            finally:
                release.set()
                self.until(lambda: not view.stop_task.running and not view._stopping)
            self.assertEqual(view.stop_button.cget("state"), "disabled")
            self.assertEqual(view.status.cget("text"), t("dashboard.stopped"))
            self.assertEqual(view.telegram_button.cget("text"), t("dashboard.start_proxy"))
            self.assertEqual(view.telegram_button.cget("state"), "normal")
            view.telegram_button.invoke()
            restart.assert_called_once_with()
            telegram.assert_not_called()
            self.until(lambda: view.stop_button.cget("state") == "normal")
            self.assertEqual(view.telegram_button.cget("text"), t("dashboard.connect_telegram"))

        def test_stopped_or_missing_stop_callback_keeps_stop_disabled(self):
            callback = mock.Mock()
            view, _, _, _ = self.view({"alive": False}, on_stop=callback)
            self.assertEqual(view.stop_button.cget("state"), "disabled")
            view.stop_button.invoke()
            view.stop_proxy()
            callback.assert_not_called()
            self.assertEqual(view.telegram_button.cget("text"), t("dashboard.start_proxy"))
            view.close()
            # Existing callers may omit the new optional callback entirely.
            legacy_view, _, _, _ = self.view({"alive": True})
            self.assertEqual(legacy_view.stop_button.cget("state"), "disabled")
            legacy_view.stop_button.invoke()
            legacy_view.stop_proxy()
            self.assertFalse(legacy_view._stopping)

        def test_running_after_timeout_or_worker_error_can_be_stopped_again(self):
            callback = mock.Mock(return_value=False)
            view, restart, _, _ = self.view({"alive": True}, on_stop=callback)
            for error in (None, RuntimeError("Synthetic stop failure")):
                with self.subTest(error=error):
                    callback.side_effect = error
                    view.stop_button.invoke()
                    self.until(lambda: not view.stop_task.running and not view._stopping)
                    self.assertEqual(view.stop_button.cget("state"), "normal")
                    self.assertEqual(view.telegram_button.cget("state"), "normal")
                    self.assertEqual(view.status.cget("text"), t("dashboard.running"))
                    self.assertEqual(view.telegram_button.cget("text"), t("dashboard.connect_telegram"))
            self.assertEqual(callback.call_count, 2)
            restart.assert_not_called()

        def test_closing_while_stopping_cancels_ui_poll_and_allows_worker_to_finish(self):
            entered, release, finished = threading.Event(), threading.Event(), threading.Event()

            def stop():
                entered.set()
                try:
                    release.wait(3)
                finally:
                    finished.set()

            callback = mock.Mock(side_effect=stop)
            view, restart, _, closed = self.view({"alive": True}, on_stop=callback)
            try:
                view.stop_button.invoke()
                self.assertTrue(entered.wait(2))
                self.pump(60)
                view.close()
                self.assertTrue(view.stop_task.closed)
                self.assertIsNone(view.stop_task.pending)
                closed.assert_called_once_with()
            finally:
                release.set()
                self.assertTrue(finished.wait(2))
                self.pump(100)
            view.refresh()
            callback.assert_called_once_with()
            restart.assert_not_called()
            self.assertFalse(self.errors)

        def test_stop_and_connect_actions_fit_minimum_hero_in_both_languages_and_themes(self):
            for language in ("ru", "en"):
                for appearance in ("light", "dark"):
                    with self.subTest(language=language, appearance=appearance):
                        set_language(language)
                        apply_ctk_appearance(self.ctk, appearance)
                        view, _, _, _ = self.view({"alive": True}, on_stop=mock.Mock())
                        self.assertEqual(view.stop_button.cget("text"), t("dashboard.stop_proxy"))
                        self.assertNotIn("dashboard.", view.stop_button.cget("text"))
                        for button in (view.stop_button, view.telegram_button):
                            self.assertInside(button, view.overview._parent_canvas)
                            self.assertInside(button._text_label, button)
                        self.assertInside(view.endpoint.master, view.overview._parent_canvas)
                        # Diagnostics and the branded sidebar share this
                        # minimum-size window. An embedded scrollable frame
                        # must follow its canvas after construction and resize.
                        self.assertLessEqual(abs(view.overview.winfo_width()
                                                 - view.overview._parent_canvas.winfo_width()), 1)
                        self.assertLessEqual(view.connection_diagnostics.frame.winfo_x()
                                             + view.connection_diagnostics.frame.winfo_width(),
                                             view.overview._parent_canvas.winfo_width() + 1)
                        self.assertInside(view.updates.frame, view.root)
                        first, second = view.telegram_button, view.stop_button
                        overlap_width = min(first.winfo_rootx() + first.winfo_width(),
                                            second.winfo_rootx() + second.winfo_width()) - max(
                                                first.winfo_rootx(), second.winfo_rootx())
                        overlap_height = min(first.winfo_rooty() + first.winfo_height(),
                                             second.winfo_rooty() + second.winfo_height()) - max(
                                                 first.winfo_rooty(), second.winfo_rooty())
                        self.assertTrue(overlap_width <= 1 or overlap_height <= 1)
                        view.root.geometry("1080x760+12000+12000")
                        self.wait_layout(view, size=(1080, 760))
                        view.root.geometry("860x640+12000+12000")
                        self.wait_layout(view)
                        self.assertInside(view.endpoint.master, view.overview._parent_canvas)
                        self.assertInside(view.updates.frame, view.root)
                        self.assertLessEqual(abs(view.overview.winfo_width()
                                                 - view.overview._parent_canvas.winfo_width()), 1)
                        view.close()


if __name__ == "__main__":
    if _NATIVE_MODE:
        sys.argv.remove("--native-run")
    unittest.main()
