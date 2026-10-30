"""Applied-state snapshots and settings navigation, without user profiles."""
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from proxy.balancer import balancer
from proxy.config import ProxyConfig
from utils import tray_common
from utils.default_config import default_tray_config


class AppliedDiagnosticsTest(unittest.TestCase):
    def setUp(self):
        self.runtime = ProxyConfig()
        self.config = default_tray_config()
        self.config.update(port=19341, helper_enabled=False, helper_mode="direct")
        self.state = mock.patch.object(tray_common, "_proxy_diagnostics_state", (0, None))
        self.runtime_patch = mock.patch.object(tray_common, "proxy_config", self.runtime)
        self.running = mock.patch.object(tray_common, "proxy_running", return_value=True)
        for patcher in (self.state, self.runtime_patch, self.running):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.assertTrue(tray_common.apply_proxy_config(self.config))

    def test_saved_changes_invalidate_without_pretending_they_are_applied(self):
        old = tray_common.diagnostics_snapshot(self.config)
        self.config["port"] = 19342
        current = tray_common.diagnostics_snapshot(self.config)
        self.assertEqual(current.port, 19341)
        self.assertNotEqual(current.identity, old.identity)
        self.config["verbose"] = not self.config["verbose"]
        self.assertEqual(tray_common.diagnostics_snapshot(self.config).identity, current.identity)

    def test_active_cache_and_refreshed_catalog_are_independent_copies(self):
        with mock.patch.object(balancer, "domains", ["one.example", "two.example"]):
            current = tray_common.diagnostics_snapshot(self.config)
            self.assertEqual(current.cf_domains, ("one.example", "two.example"))
            self.runtime.port = 1
            balancer.domains.append("three.example")
            newer = tray_common.diagnostics_snapshot(self.config)
            self.assertEqual(current.port, 19341)
            self.assertEqual(newer.port, 19341)
            self.assertEqual(current.cf_domains, ("one.example", "two.example"))
            self.assertNotEqual(current.identity, newer.identity)

    def test_snapshot_does_not_wait_for_proxy_stop_lock(self):
        acquired, release = threading.Event(), threading.Event()

        def hold_lock():
            with tray_common._proxy_lifecycle_lock:
                acquired.set()
                release.wait(3)

        worker = threading.Thread(target=hold_lock, daemon=True)
        worker.start()
        self.assertTrue(acquired.wait(1))
        finished = threading.Event()
        reader = threading.Thread(target=lambda: (tray_common.diagnostics_snapshot(self.config),
                                                   finished.set()), daemon=True)
        reader.start()
        try:
            self.assertTrue(finished.wait(.5), "UI snapshot waited on a proxy lifecycle lock")
        finally:
            release.set()
            worker.join(2)
            reader.join(2)

    def test_stop_invalidates_even_when_an_identical_profile_will_be_reused(self):
        before = tray_common.diagnostics_snapshot(self.config)
        with mock.patch.object(tray_common, "_proxy_thread", None), \
                mock.patch.object(tray_common, "_async_stop", None), \
                mock.patch.object(tray_common, "_proxy_stop_requested", None):
            self.assertTrue(tray_common.stop_proxy())
        self.assertNotEqual(tray_common.diagnostics_snapshot(self.config).identity, before.identity)

    def test_fallback_lock_recognizes_renamed_executable_and_rejects_reused_pid(self):
        process = mock.Mock()
        process.create_time.return_value = 1234.0
        process.exe.return_value = str(Path.cwd() / "TG Proxy renamed test.exe")
        with mock.patch.object(tray_common, "IS_FROZEN", True), \
                mock.patch.object(sys, "executable", process.exe.return_value):
            self.assertTrue(tray_common._same_process({"create_time": 1234.0}, process))
            self.assertFalse(tray_common._same_process({"create_time": 1.0}, process))
            process.exe.return_value = str(Path.cwd() / "Other.exe")
            self.assertFalse(tray_common._same_process({"create_time": 1234.0}, process))


class InitialSettingsPageTest(unittest.TestCase):
    def test_native_routes_page_and_compatible_default(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--native-settings"],
            capture_output=True, text=True, timeout=30,
        )
        if "NATIVE_DISPLAY_UNAVAILABLE" in result.stdout:
            self.skipTest("Native Tk display is unavailable")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__" and "--native-settings" in sys.argv:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import customtkinter as ctk
    from tkinter import TclError
    from ui.ctk_theme import ctk_theme_for_platform
    from ui.i18n import t
    from ui.settings_form import install_tray_config_form

    try:
        app = ctk.CTk()
    except TclError:
        print("NATIVE_DISPLAY_UNAVAILABLE")
        raise SystemExit(0)
    app.withdraw()
    failures = []
    app.report_callback_exception = lambda *args: failures.append(args)
    try:
        for page, routes_visible in (("routes", True), ("connection", False), ("unknown", False)):
            window = ctk.CTkToplevel(app)
            window.geometry("600x700+12000+12000")
            frame = ctk.CTkFrame(window)
            frame.pack(fill="both", expand=True)
            config = default_tray_config()
            widgets = install_tray_config_form(
                ctk, frame, ctk_theme_for_platform(), config, config, initial_page=page,
            )
            app.update()
            node = widgets.dc_textbox
            while not isinstance(node, ctk.CTkScrollableFrame):
                node = node.master
            navigation = next(w for w in frame.winfo_children() if isinstance(w, ctk.CTkSegmentedButton))
            assert (node._parent_frame.winfo_manager() == "grid") is routes_visible, page
            assert navigation.get() == (t("settings.tab.routes") if routes_visible else t("settings.tab.connection"))
            window.destroy()
            app.update()
        assert not failures, failures
    finally:
        app.destroy()
