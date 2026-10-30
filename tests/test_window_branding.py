import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tkinter import TclError

from ui import ctk_theme


class IconWindow:
    def __init__(self):
        self.icons = []
        self.jobs = {}
        self.bindings = {}

    def winfo_exists(self):
        return True

    def iconbitmap(self, *args, **kwargs):
        self.icons.append((args, kwargs))

    def after(self, delay, callback):
        self.jobs["icon-job"] = callback
        return "icon-job"

    def after_cancel(self, token):
        self.jobs.pop(token, None)

    def bind(self, event, callback, add=None):
        self.bindings[event] = callback


class WindowBrandingTest(unittest.TestCase):
    def setUp(self):
        # IconWindow is a Tk scheduling fixture, not a native HWND. The actual
        # WM_SETICON/WM_GETICON path is covered by test_windows_identity.
        native = mock.patch("utils.windows_identity.install_native_icons")
        self.native_icons = native.start()
        self.addCleanup(native.stop)

    def test_frozen_asset_resolution_uses_bundle_data_directory(self):
        with mock.patch.object(sys, "_MEIPASS", "C:/synthetic-bundle", create=True):
            self.assertEqual(ctk_theme.app_icon_path(), Path("C:/synthetic-bundle/icon.ico"))

    def test_our_icon_is_restored_after_ctk_overwrites_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "icon.ico"
            path.touch()
            window = IconWindow()
            with mock.patch.object(ctk_theme.sys, "platform", "win32"), \
                    mock.patch.object(ctk_theme, "app_icon_path", return_value=path):
                ctk_theme.install_window_icon(window)
            self.assertEqual(window.icons[-1], ((str(path),), {}))
            window.iconbitmap("CustomTkinter_icon_Windows.ico")
            window.jobs["icon-job"]()
            self.assertEqual(window.icons[-1], ((str(path),), {}))
            self.assertEqual(self.native_icons.call_count, 2)
            self.native_icons.assert_called_with(window, path)

    def test_hidden_root_can_set_default_icon_and_destroy_cancels_delayed_work(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "icon.ico"
            path.touch()
            window = IconWindow()
            with mock.patch.object(ctk_theme.sys, "platform", "win32"), \
                    mock.patch.object(ctk_theme, "app_icon_path", return_value=path):
                ctk_theme.install_window_icon(window, default=True)
            self.assertEqual(window.icons[-1], ((), {"default": str(path)}))
            window.bindings["<Destroy>"](SimpleNamespace(widget=window))
            self.assertFalse(window.jobs)

    def test_missing_or_invalid_icon_is_reported_without_breaking_window(self):
        window = IconWindow()
        with mock.patch.object(ctk_theme.sys, "platform", "win32"), \
                mock.patch.object(ctk_theme, "app_icon_path", return_value=Path("missing-TG-Proxy.ico")), \
                self.assertLogs(ctk_theme.log, level="WARNING") as captured:
            ctk_theme.install_window_icon(window)
        self.assertIn("Application icon is missing", captured.output[0])
        self.assertFalse(window.icons)
        self.assertFalse(window.jobs)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "icon.ico"
            path.touch()
            with mock.patch.object(ctk_theme.sys, "platform", "win32"), \
                    mock.patch.object(ctk_theme, "app_icon_path", return_value=path), \
                    mock.patch.object(window, "iconbitmap", side_effect=TclError("bad icon")), \
                    self.assertLogs(ctk_theme.log, level="WARNING") as captured:
                ctk_theme.install_window_icon(window)
            self.assertIn("Could not set application icon (TclError)", captured.output[0])


if __name__ == "__main__":
    unittest.main()
