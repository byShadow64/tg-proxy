"""The production dialog factory must map windows without manual deiconify()."""
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

from tkinter import TclError

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ui import ctk_theme
from ui.ctk_tray_ui import install_tray_config_buttons, tray_settings_scroll_and_footer
from ui.helper_settings import build_helper_settings
from ui.settings_form import install_tray_config_form
from ui.i18n import t
from utils.default_config import default_tray_config

_NATIVE_MODE = "--native-run" in sys.argv


class ToplevelLifecycleTest(unittest.TestCase):
    def test_callback_created_dialogs_map_and_run_delayed_setup(self):
        if not _NATIVE_MODE:
            # Keep a separate Tcl interpreter lifecycle from other native UI
            # test modules; CTk caches font/images tied to its first Tk root.
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--native-run"],
                capture_output=True, text=True, timeout=20,
            )
            if "NATIVE_DISPLAY_UNAVAILABLE" in result.stdout:
                self.skipTest("Native Tk display is unavailable")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return
        import customtkinter as ctk

        try:
            app = ctk.CTk()
        except TclError as exc:
            print("NATIVE_DISPLAY_UNAVAILABLE")
            self.skipTest(f"Native Tk display is unavailable: {exc}")
        self.addCleanup(app.destroy)
        app.withdraw()
        errors = []
        app.report_callback_exception = lambda *args: errors.append(args)
        theme = ctk_theme.ctk_theme_for_platform()

        def offscreen(window, width, height):
            window.geometry(f"{width}x{height}+12000+12000")

        # Preserve the production creation/mapping lifecycle without taking
        # focus from the user's desktop during this offscreen regression test.
        with mock.patch.object(ctk_theme, "center_ctk_geometry", offscreen), \
                mock.patch.object(ctk.CTkToplevel, "focus_force") as focus, \
                mock.patch.object(ctk.CTkToplevel, "lift") as lift, \
                mock.patch.object(ctk.CTkToplevel, "iconbitmap", autospec=True,
                                  side_effect=ctk.CTkToplevel.iconbitmap) as icons:
            for kind in ("message", "settings", "helper"):
                with self.subTest(kind=kind):
                    windows, delayed, forms = [], [], []

                    def build():
                        window = ctk_theme.create_ctk_toplevel(
                            ctk, title=f"Offscreen {kind}", width=680, height=680,
                            theme=theme, topmost=False, resizable=kind != "message",
                            after_create=delayed.append,
                        )
                        windows.append(window)
                        if kind == "helper":
                            build_helper_settings(
                                ctk, window, theme, {}, save_config=lambda _: None,
                                restart=lambda _: None, on_saved=lambda: None,
                            )
                        elif kind == "settings":
                            window.minsize(560, 560)
                            frame = ctk_theme.main_content_frame(
                                ctk, window, theme, padx=28, pady=24,
                            )
                            content, footer = tray_settings_scroll_and_footer(ctk, frame, theme)
                            config = default_tray_config()
                            config["check_updates"] = False
                            forms.append(install_tray_config_form(
                                ctk, content, theme, config, config, show_autostart=True,
                            ))
                            install_tray_config_buttons(
                                ctk, footer, theme, on_save=lambda: None, on_cancel=lambda: None,
                            )

                    try:
                        app.after(0, build)
                        ready = ctk.BooleanVar(master=app, value=False)
                        deadline = time.monotonic() + 3

                        def await_mapping():
                            mapped = (
                                windows and delayed == windows
                                and windows[0].state() == "normal"
                                and windows[0].winfo_ismapped()
                                and not getattr(windows[0], "_windows_set_titlebar_color_called", False)
                            )
                            if mapped or time.monotonic() >= deadline:
                                ready.set(True)
                            else:
                                app.after(20, await_mapping)

                        app.after(20, await_mapping)
                        app.wait_variable(ready)
                        app.update()
                        self.assertFalse(errors)
                        self.assertEqual(len(windows), 1)
                        window = windows[0]
                        self.assertEqual(window.state(), "normal")
                        self.assertTrue(window.winfo_ismapped())
                        self.assertEqual(delayed, [window])
                        if sys.platform == "win32":
                            # Windows Tk does not return the ICO filename when
                            # queried. Wrap the real setter instead and verify
                            # the final successful call after CTk's own timer.
                            calls = [call for call in icons.call_args_list
                                     if call.args[0] is window and len(call.args) > 1]
                            self.assertEqual(Path(calls[-1].args[1]), ctk_theme.app_icon_path())
                        # Query Tk directly: CTk.resizable() schedules a redraw
                        # even when called only to read the current values.
                        resize = window.tk.call("wm", "resizable", window._w)
                        self.assertEqual(tuple(map(int, resize)),
                                         (0, 0) if kind == "message" else (1, 1))
                        if kind == "settings":
                            def descendants(widget):
                                for child in widget.winfo_children():
                                    yield child
                                    yield from descendants(child)

                            appearance = next(
                                widget for widget in descendants(window)
                                if isinstance(widget, ctk.CTkComboBox)
                                and widget.cget("variable") is forms[0].appearance_var
                            )
                            focus.reset_mock()
                            lift.reset_mock()
                            next_mode = "light" if ctk.get_appearance_mode() == "Dark" else "dark"
                            appearance.cget("command")(t(f"appearance.{next_mode}"))
                            restored = ctk.BooleanVar(master=app, value=False)
                            app.after(350, lambda: restored.set(True))
                            app.wait_variable(restored)
                            app.update()
                            self.assertEqual(lift.call_count, 1)
                            self.assertEqual(focus.call_count, 1)
                            self.assertFalse(errors)
                    finally:
                        for window in windows:
                            window.destroy()


if __name__ == "__main__":
    if _NATIVE_MODE:
        sys.argv.remove("--native-run")
    unittest.main()
