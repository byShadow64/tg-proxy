"""Production settings are owned, visible and reusable after CTk's remapping."""
import subprocess
import sys
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from tkinter import TclError
from unittest import mock

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_NATIVE = "--native-run" in sys.argv


@unittest.skipUnless(sys.platform == "win32", "Windows WM ownership regression")
class SettingsForegroundTest(unittest.TestCase):
    def test_settings_stay_above_overview_and_survive_owner_lifecycle(self):
        if not _NATIVE:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--native-run"],
                capture_output=True, text=True, timeout=60,
            )
            if "NATIVE_DISPLAY_UNAVAILABLE" in result.stdout:
                self.skipTest("Native Tk display unavailable")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return
        import customtkinter as ctk
        import windows as app
        from ui import ctk_theme
        from ui.i18n import set_language, t
        from utils.default_config import default_tray_config

        try:
            root = ctk.CTk()
        except TclError:
            print("NATIVE_DISPLAY_UNAVAILABLE")
            self.skipTest("Native Tk display unavailable")
        root.withdraw()
        errors = []
        root.report_callback_exception = lambda *args: errors.append(args)
        self.addCleanup(root.destroy)

        def pump(delay=350):
            done = ctk.BooleanVar(master=root, value=False)
            root.after(delay, lambda: done.set(True))
            root.wait_variable(done)
            root.update()
            self.assertFalse(errors)

        def dashboard():
            window = ctk.CTkToplevel(root)
            window.title("TG Proxy foreground regression")
            window.geometry("860x640+12000+12000")
            app._dashboard_window = window
            pump()
            return window

        def assert_above(settings, overview):
            self.assertTrue(settings.winfo_ismapped())
            self.assertEqual(str(settings.transient()), str(overview))
            order = tuple(str(item) for item in root.tk.call("wm", "stackorder", root._w))
            self.assertGreater(order.index(str(settings)), order.index(str(overview)), order)
            self.assertFalse(bool(settings.attributes("-topmost")))
            self.assertEqual(settings.master, root)  # A sibling, not destroyed with Overview.

        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)

        with ExitStack() as stack:
            for name in ("_settings_window", "_settings_widgets", "_settings_requested_page",
                         "_dashboard_window", "_dashboard_view", "_tray_icon"):
                stack.enter_context(mock.patch.object(app, name, None))
            stack.enter_context(mock.patch.object(app, "_settings_opening", False))
            stack.enter_context(mock.patch.object(app, "ensure_ctk_thread", return_value=True))
            stack.enter_context(mock.patch.object(app, "is_autostart_enabled", return_value=False))
            stack.enter_context(mock.patch.object(app, "_supports_autostart", return_value=False))
            stack.enter_context(mock.patch.object(app, "ctk_run_dialog",
                                                 side_effect=lambda build: build(threading.Event())))
            stack.enter_context(mock.patch.object(ctk_theme, "center_ctk_geometry",
                                                 side_effect=lambda w, x, y: w.geometry(f"{x}x{y}+12040+12040")))
            save = stack.enter_context(mock.patch.object(app, "save_config"))
            popup = stack.enter_context(mock.patch.object(app, "_show_error"))
            for language in ("ru", "en"):
                for mode in ("light", "dark"):
                    with self.subTest(language=language, appearance=mode):
                        config = default_tray_config()
                        config.update(language=language, appearance=mode, check_updates=False,
                                      auto_install_updates=False)
                        app._config = config
                        set_language(language)
                        ctk.set_appearance_mode(mode)
                        overview = dashboard()
                        app._edit_config_dialog()
                        settings = app._settings_window
                        self.assertIsNotNone(settings)
                        pump()
                        assert_above(settings, overview)
                        form = app._settings_widgets
                        form.port_var.set("19349")

                        # A click/restore on the parent must not cover its owned form.
                        overview.lift()
                        overview.focus_force()
                        pump(30)
                        assert_above(settings, overview)

                        # Appearance changes remap both top-level titlebars.
                        ctk.set_appearance_mode("dark" if mode == "light" else "light")
                        pump()
                        assert_above(settings, overview)

                        # Exercise the actual settings combobox callback, not
                        # just CTk's global appearance API. It runs while this
                        # dialog is focused and its Application page is shown.
                        form.select_page("application")
                        combo = next(widget for widget in descendants(settings)
                                     if isinstance(widget, ctk.CTkComboBox)
                                     and widget.cget("variable") is form.appearance_var)
                        for chosen_mode in ("dark", "light"):
                            settings.focus_force()
                            combo._entry.focus_set()
                            pump(30)
                            combo._dropdown_callback(t(f"appearance.{chosen_mode}"))
                            pump()
                            self.assertIs(app._settings_window, settings)
                            self.assertEqual(form.port_var.get(), "19349")
                            self.assertEqual(form.appearance_var.get(), t(f"appearance.{chosen_mode}"))
                            assert_above(settings, overview)

                        # The frozen Windows UI can remain withdrawn after
                        # CTk's nested redraw callbacks. Model that observed
                        # postcondition after draining earlier owner-map work;
                        # the real settings callback must restore it by itself.
                        set_appearance = ctk.set_appearance_mode

                        def redraw_leaving_dialog_withdrawn(choice):
                            set_appearance(choice)
                            pump(200)
                            settings.withdraw()

                        with mock.patch.object(ctk, "set_appearance_mode",
                                               side_effect=redraw_leaving_dialog_withdrawn):
                            combo._dropdown_callback(t("appearance.light"))
                        pump()
                        assert_above(settings, overview)
                        self.assertEqual(form.port_var.get(), "19349")
                        app._edit_config_dialog(initial_page="routes")
                        app._edit_config_dialog()
                        pump()
                        self.assertIs(app._settings_window, settings)
                        self.assertIs(app._settings_widgets, form)
                        self.assertEqual(form.port_var.get(), "19349")
                        assert_above(settings, overview)

                        # A tray request can restore settings while Overview is minimized.
                        overview.iconify()
                        pump()
                        app._edit_config_dialog()
                        pump()
                        self.assertTrue(settings.winfo_viewable())
                        self.assertEqual(str(settings.transient()), "")
                        overview.deiconify()
                        pump()
                        app._edit_config_dialog()
                        pump()
                        assert_above(settings, overview)

                        # Owner close preserves the unsaved form and removes stale bindings.
                        overview.destroy()
                        app._dashboard_window = None
                        pump()
                        self.assertTrue(settings.winfo_exists())
                        self.assertEqual(form.port_var.get(), "19349")
                        self.assertEqual(str(settings.transient()), "")
                        overview = dashboard()
                        app._edit_config_dialog()
                        pump()
                        assert_above(settings, overview)

                        # Delayed activation must not act on a closed/replaced window.
                        app._edit_config_dialog()
                        settings.destroy()
                        overview.destroy()
                        app._dashboard_window = None
                        pump()
                        app._edit_config_dialog(initial_page="routes")
                        replacement = app._settings_window
                        # A standalone tray editor has no Overview owner. CTk's
                        # delayed titlebar redraw can still leave it withdrawn;
                        # presentation must restore this requested editor too.
                        replacement.after(50, replacement.withdraw)
                        pump()
                        self.assertIsNot(replacement, settings)
                        self.assertTrue(replacement.winfo_viewable())
                        self.assertEqual(str(replacement.transient()), "")
                        replacement.destroy()
                        pump()
            save.assert_not_called()
            popup.assert_not_called()


if __name__ == "__main__":
    if _NATIVE:
        sys.argv.remove("--native-run")
    unittest.main()
