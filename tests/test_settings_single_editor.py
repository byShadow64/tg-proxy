"""Repeated settings requests must not create stale competing configuration forms."""
import sys
import threading
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock
from tkinter import TclError


class Window:
    def __init__(self):
        self.closed = False
        self.deiconify = mock.Mock()
        self.lift = mock.Mock()
        self.focus_force = mock.Mock()
        self.minsize = mock.Mock()
        self.protocol = mock.Mock()

    def winfo_exists(self):
        return not self.closed

    def destroy(self):
        self.closed = True


@unittest.skipUnless(sys.platform == "win32", "Windows settings integration")
class SingleSettingsEditorTest(unittest.TestCase):
    def setUp(self):
        import windows
        self.app = windows
        self.events, self.windows, self.widgets = [], [], []
        self.stack = self.enterContext(ExitStack())
        for name, value in (("_settings_window", None), ("_settings_widgets", None),
                            ("_settings_opening", False), ("_settings_requested_page", None),
                            ("_config", {"port": 19341}), ("_tray_icon", None)):
            self.stack.enter_context(mock.patch.object(self.app, name, value))
        self.stack.enter_context(mock.patch.object(self.app, "ensure_ctk_thread", return_value=True))
        self.stack.enter_context(mock.patch.object(self.app, "ctk_theme_for_platform", return_value=object()))
        self.stack.enter_context(mock.patch.object(self.app, "main_content_frame", return_value=object()))
        self.stack.enter_context(mock.patch.object(self.app, "tray_settings_scroll_and_footer",
                                                 return_value=(object(), object())))
        self.stack.enter_context(mock.patch.object(self.app, "_supports_autostart", return_value=False))
        self.stack.enter_context(mock.patch.object(self.app, "is_autostart_enabled", return_value=False))
        self.stack.enter_context(mock.patch.object(self.app, "install_tray_config_buttons"))
        self.present = self.stack.enter_context(mock.patch.object(self.app, "present_ctk_dialog"))
        self.popup = self.stack.enter_context(mock.patch.object(self.app, "_show_error"))
        self.save = self.stack.enter_context(mock.patch.object(self.app, "save_config"))
        self.dialog = self.stack.enter_context(mock.patch.object(self.app, "SettingsDialog"))
        self.create = self.stack.enter_context(mock.patch.object(self.app, "create_ctk_toplevel",
                                                               side_effect=self.new_window))
        self.form = self.stack.enter_context(mock.patch.object(self.app, "install_tray_config_form",
                                                             side_effect=self.new_form))
        self.stack.enter_context(mock.patch.object(self.app, "ctk_run_dialog", side_effect=self.run_dialog))

    def new_window(self, *args, **kwargs):
        window = Window()
        self.windows.append(window)
        return window

    def new_form(self, *args, **kwargs):
        widgets = SimpleNamespace(helper_busy_var=object(), select_page=mock.Mock())
        self.widgets.append(widgets)
        return widgets

    def run_dialog(self, build):
        done = threading.Event()
        self.events.append(done)
        build(done)

    def test_repeated_requests_activate_one_editor_and_routes_preserve_its_form(self):
        self.app._edit_config_dialog()
        form = self.widgets[0]
        self.app._edit_config_dialog(initial_page="routes")
        self.app._edit_config_dialog()
        self.create.assert_called_once()
        self.form.assert_called_once()
        self.dialog.assert_called_once()
        self.assertIs(self.app._settings_widgets, form)
        form.select_page.assert_called_once_with("routes")
        self.assertEqual(self.present.call_count, 3)
        self.present.assert_called_with(self.windows[0], owner=self.app._dashboard_window)
        self.assertFalse(self.events[0].is_set())
        self.assertTrue(all(event.is_set() for event in self.events[1:]))
        self.save.assert_not_called()

    def test_nested_tk_events_coalesce_before_widget_construction_finishes(self):
        def form(*args, **kwargs):
            self.app._edit_config_dialog(initial_page="routes")
            self.app._edit_config_dialog()
            return self.new_form()

        self.form.side_effect = form
        self.app._edit_config_dialog()
        self.create.assert_called_once()
        self.form.assert_called_once()
        self.widgets[0].select_page.assert_called_once_with("routes")
        self.assertFalse(self.app._settings_opening)
        self.assertFalse(self.events[0].is_set())
        self.assertTrue(all(event.is_set() for event in self.events[1:]))

    def test_close_releases_editor_and_next_open_uses_new_configuration(self):
        self.app._edit_config_dialog()
        finish = self.dialog.call_args.kwargs["finish"]
        self.app._config["port"] = 19342
        finish()
        self.assertIsNone(self.app._settings_window)
        self.assertIsNone(self.app._settings_widgets)
        self.assertTrue(self.events[0].is_set())
        self.assertTrue(self.windows[0].closed)
        self.app._edit_config_dialog(initial_page="routes")
        self.assertEqual(self.create.call_count, 2)
        self.assertEqual(self.form.call_args.args[3]["port"], 19342)
        self.assertEqual(self.form.call_args.kwargs["initial_page"], "routes")
        self.assertFalse(self.events[1].is_set())

    def test_failed_construction_cleans_partial_window_and_allows_retry(self):
        self.form.side_effect = RuntimeError("Synthetic failure")
        with self.assertLogs(self.app.log, level="ERROR"):
            self.app._edit_config_dialog()
        self.assertTrue(self.windows[0].closed)
        self.assertTrue(self.events[0].is_set())
        self.assertIsNone(self.app._settings_window)
        self.assertFalse(self.app._settings_opening)
        self.popup.assert_called_once()
        self.form.side_effect = self.new_form
        self.app._edit_config_dialog()
        self.assertIs(self.app._settings_window, self.windows[1])
        self.assertFalse(self.windows[1].closed)
        self.assertFalse(self.events[1].is_set())

    def test_recovered_interpreter_does_not_query_stale_settings_again(self):
        old = Window()
        old.winfo_exists = mock.Mock(side_effect=TclError("Synthetic closed interpreter"))
        self.app._settings_window = old
        self.app._edit_config_dialog()
        self.create.assert_called_once()
        self.assertIs(self.app._settings_window, self.windows[0])
        old.deiconify.assert_not_called()
        self.assertFalse(self.events[0].is_set())


if __name__ == "__main__":
    unittest.main()
