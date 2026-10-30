"""Native settings route probes use cancellation and never touch the network."""
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

_NATIVE = "--native-route-run" in sys.argv


if not _NATIVE:
    class RouteSettingsProcessTest(unittest.TestCase):
        def test_native_route_settings_lifecycle(self):
            result = subprocess.run(
                [sys.executable, "-B", str(Path(__file__).resolve()), "--native-route-run"],
                capture_output=True, text=True, timeout=110,
            )
            if "NATIVE_DISPLAY_UNAVAILABLE" in result.stdout:
                self.skipTest("Native Tk display is unavailable")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ControlledProbe:
    def __init__(self, result):
        self.result = result
        self.entered = threading.Event()
        self.cancelled = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.cancel = self.thread = None
        self.calls = 0

    def __call__(self, domains, *, secure, cancel):
        self.calls += 1
        self.cancel, self.thread = cancel, threading.current_thread()
        self.entered.set()
        deadline = time.monotonic() + 4
        try:
            while not self.release.is_set():
                if cancel.is_set():
                    self.cancelled.set()
                if time.monotonic() >= deadline:
                    raise TimeoutError("Synthetic route worker was not released")
                self.release.wait(.01)
            return self.result
        finally:
            self.finished.set()


if _NATIVE:
    from ui import settings_form as form
    from ui.ctk_theme import apply_ctk_appearance, ctk_theme_for_platform
    from ui.i18n import get_config_language, set_language, t
    from utils.default_config import default_tray_config

    def descendants(widget):
        for child in widget.winfo_children():
            yield child
            yield from descendants(child)

    class NativeRouteSettingsTest(unittest.TestCase):
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
            self.windows, self.probes, self.errors = [], [], []
            self.app.report_callback_exception = lambda *args: self.errors.append(args)
            self.stack = self.enterContext(ExitStack())
            self.addCleanup(set_language, get_config_language())
            self.addCleanup(self.ctk.set_appearance_mode, self.ctk.get_appearance_mode())
            self.runners = {name: self.stack.enter_context(mock.patch.object(
                form, name, side_effect=AssertionError("Real route networking is forbidden")))
                for name in ("run_cfproxy_multi_test", "run_cfproxy_auto_test", "run_cfworker_multi_test")}
            self.multi = self.stack.enter_context(mock.patch.object(form, "show_multi_connectivity_results"))
            self.auto = self.stack.enter_context(mock.patch.object(form, "show_connectivity_results"))
            self.stack.enter_context(mock.patch.object(form.balancer, "domains", ["auto.example"]))

        def tearDown(self):
            for probe in self.probes:
                probe.release.set()
                if probe.thread is not None:
                    probe.thread.join(2)
                    self.assertFalse(probe.thread.is_alive())
            for window in self.windows:
                if window.winfo_exists():
                    window.destroy()
            self.pump(50)
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
                    self.fail("Route settings did not reach the expected state")
                self.pump()

        def editor(self, language, appearance):
            apply_ctk_appearance(self.ctk, appearance)
            config = default_tray_config()
            config.update(language=language, appearance=appearance, port=19341,
                          cfproxy_user_domain_enabled=True, cfproxy_user_domain=["one.example"],
                          cfproxy_worker_enabled=True, cfproxy_worker_domain=["worker.example"])
            window = self.ctk.CTkToplevel(self.app)
            self.windows.append(window)
            window.geometry("860x640+12000+12000")
            frame = self.ctk.CTkFrame(window)
            frame.pack(fill="both", expand=True)
            widgets = form.install_tray_config_form(
                self.ctk, frame, ctk_theme_for_platform(), config, config, initial_page="routes")
            window.deiconify()
            self.pump(50)
            self.assertEqual((window.winfo_width(), window.winfo_height()), (860, 640))
            return window, widgets, config

        def test_button_cancel_cleanup_repeat_and_close_in_both_languages_and_themes(self):
            modes = (("cf", "run_cfproxy_multi_test", "_on_cf_test"),
                     ("auto", "run_cfproxy_auto_test", "_on_cf_test"),
                     ("worker", "run_cfworker_multi_test", "_on_cfworker_test"))
            for language in ("ru", "en"):
                for appearance in ("light", "dark"):
                    for kind, runner_name, callback_name in modes:
                        with self.subTest(language=language, appearance=appearance, kind=kind):
                            window, widgets, _ = self.editor(language, appearance)
                            if kind == "auto":
                                widgets.cfproxy_user_domain_enabled_var.set(False)
                            button = next(w for w in descendants(window)
                                if isinstance(w, self.ctk.CTkButton)
                                and getattr(getattr(w, "_command", None), "__name__", "") == callback_name)
                            self.multi.reset_mock()
                            self.auto.reset_mock()
                            runner = self.runners[runner_name]
                            runner.reset_mock()
                            value = ("auto.example", {1: True}) if kind == "auto" else {"one.example": {1: True}}
                            first = ControlledProbe(value)
                            self.probes.append(first)
                            runner.side_effect = first
                            button.invoke()
                            self.until(first.entered.is_set)
                            self.assertIsInstance(first.cancel, threading.Event)
                            self.assertNotEqual(first.thread.ident, threading.get_ident())
                            self.assertEqual(button.cget("text"), t("button.cancel"))
                            button.invoke()
                            self.until(first.cancelled.is_set)
                            self.assertEqual(button.cget("text"), t("button.cancelling"))
                            self.assertEqual(button.cget("state"), "disabled")
                            # Editing a Worker field during cleanup must not
                            # re-enable another Cancel/repeat action prematurely.
                            if kind == "worker":
                                widgets.cfproxy_worker_domain_var.set("changed.example")
                                self.assertEqual(button.cget("state"), "disabled")
                            self.pump(60)
                            self.assertEqual(button.cget("state"), "disabled")
                            button.invoke()
                            self.assertEqual(first.calls, 1)
                            first.release.set()
                            self.until(lambda: button.cget("text") == t("button.test"))
                            self.assertEqual(button.cget("state"), "normal")
                            self.multi.assert_not_called()
                            self.auto.assert_not_called()

                            second = ControlledProbe(value)
                            self.probes.append(second)
                            runner.side_effect = second
                            button.invoke()
                            self.until(second.entered.is_set)
                            self.assertIsNot(second.cancel, first.cancel)
                            self.assertFalse(second.cancel.is_set())
                            second.release.set()
                            self.until(lambda: button.cget("text") == t("button.test"))
                            (self.auto if kind == "auto" else self.multi).assert_called_once()
                            self.multi.reset_mock()
                            self.auto.reset_mock()

                            late = ControlledProbe(value)
                            self.probes.append(late)
                            runner.side_effect = late
                            button.invoke()
                            self.until(late.entered.is_set)
                            window.destroy()
                            self.assertTrue(late.cancel.is_set())
                            late.release.set()
                            self.until(late.finished.is_set)
                            self.pump(80)
                            self.multi.assert_not_called()
                            self.auto.assert_not_called()

        def test_routes_navigation_preserves_unsaved_fields(self):
            for language in ("ru", "en"):
                for appearance in ("light", "dark"):
                    with self.subTest(language=language, appearance=appearance):
                        window, widgets, config = self.editor(language, appearance)
                        original_host = config["host"]
                        widgets.select_page("connection")
                        widgets.host_var.set("127.0.0.2")
                        widgets.port_var.set("19342")
                        widgets.cfproxy_user_domain_var.set("unsaved.example")
                        widgets.select_page("routes")
                        self.pump()
                        self.assertEqual(widgets.host_var.get(), "127.0.0.2")
                        self.assertEqual(widgets.port_var.get(), "19342")
                        self.assertEqual(widgets.cfproxy_user_domain_var.get(), "unsaved.example")
                        self.assertEqual(config["host"], original_host)
                        self.assertEqual(config["port"], 19341)
                        page = widgets.dc_textbox
                        while not isinstance(page, self.ctk.CTkScrollableFrame):
                            page = page.master
                        self.assertEqual(page._parent_frame.winfo_manager(), "grid")
                        window.destroy()

    if __name__ == "__main__":
        unittest.main(argv=[sys.argv[0]], verbosity=2)
