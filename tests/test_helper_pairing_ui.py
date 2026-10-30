"""Native pairing lifecycle tests; adapters use synthetic data and no network."""
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from tkinter import TclError

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from helper_pairing import b64encode
from ui import helper_pairing
from ui.ctk_theme import apply_ctk_appearance, ctk_theme_for_platform
from ui.i18n import get_config_language, set_language, t
from utils.helper_pairing import PairingCancelled, PairingResult

_NATIVE_MODE = "--native-run" in sys.argv
_CODE = "TG1." + b64encode(b"i" * 8) + "." + b64encode(b"s" * 16)
_TOKEN = "synthetic-pairing-token-" + "x" * 40


if not _NATIVE_MODE:
    class PairingProcessTest(unittest.TestCase):
        def test_native_pairing_scenarios(self):
            result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--native-run"],
                                    capture_output=True, text=True, timeout=40)
            if "NATIVE_DISPLAY_UNAVAILABLE" in result.stdout:
                self.skipTest("Native Tk display unavailable")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if _NATIVE_MODE:
    class NativePairingTest(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            import customtkinter as ctk
            cls.ctk = ctk
            try:
                cls.app = ctk.CTk()
            except TclError:
                print("NATIVE_DISPLAY_UNAVAILABLE")
                raise unittest.SkipTest("Native Tk display unavailable") from None
            cls.app.withdraw()

        @classmethod
        def tearDownClass(cls):
            cls.app.destroy()

        def setUp(self):
            self.windows, self.errors = [], []
            self.app.report_callback_exception = lambda *args: self.errors.append(args)
            self.addCleanup(set_language, get_config_language())
            set_language("en")
            apply_ctk_appearance(self.ctk, "light")
            self.theme = ctk_theme_for_platform()
            self.result = PairingResult("127.0.0.1", 18444, "a" * 64, _TOKEN)

        def tearDown(self):
            for window in self.windows:
                if window.winfo_exists():
                    window.destroy()
            self.app.update()
            self.assertFalse(self.errors)

        def pump(self, milliseconds=40):
            ready = self.ctk.BooleanVar(master=self.app, value=False)
            self.app.after(milliseconds, lambda: ready.set(True))
            self.app.wait_variable(ready)
            self.app.update()

        def until(self, condition):
            deadline = time.monotonic() + 3
            while not condition():
                if time.monotonic() >= deadline:
                    self.fail("Pairing UI did not reach expected state")
                self.pump()

        def view(self, *, callback=None, busy=None):
            window = self.ctk.CTkToplevel(self.app)
            window.withdraw()
            self.windows.append(window)
            view = helper_pairing.HelperPairing(self.ctk, window, self.theme,
                on_paired=callback or Mock(), on_busy=busy)
            view.frame.pack(fill="both", expand=True, padx=20, pady=20)
            window.geometry("500x520+12000+12000")
            window.deiconify()
            self.pump()
            view.host_var.set("127.0.0.1:18444")
            view.code_var.set(_CODE)
            return window, view

        def test_local_validation_and_masking_do_not_contact_network(self):
            with patch.object(helper_pairing, "pair_helper") as pair:
                _, view = self.view()
                self.assertTrue(view.code_entry.cget("show"))
                view.code_var.set("bad")
                view.connect_button.invoke()
                self.assertFalse(view.busy)
                self.assertEqual(view.status.cget("text"), t("pairing.invalid"))
                pair.assert_not_called()

        def test_worker_keeps_tk_responsive_and_returns_only_on_main_thread(self):
            entered, release = threading.Event(), threading.Event()
            workers, callbacks, busy = [], [], []
            main = threading.get_ident()

            def pair(host, code, port, *, cancel_event):
                self.assertEqual((host, code, port), ("127.0.0.1", _CODE, 18444))
                workers.append(threading.get_ident())
                entered.set()
                release.wait(3)
                return self.result

            with patch.object(helper_pairing, "pair_helper", side_effect=pair):
                _, view = self.view(callback=lambda result: callbacks.append((threading.get_ident(), result)),
                                    busy=busy.append)
                try:
                    view.connect_button.invoke()
                    self.assertTrue(entered.wait(1))
                    self.assertTrue(view.busy)
                    self.assertEqual(view.code_var.get(), "")
                    self.assertEqual(view.connect_button.cget("state"), "disabled")
                    heartbeat = []
                    self.app.after(0, lambda: heartbeat.append(True))
                    self.pump()
                    self.assertEqual(heartbeat, [True])
                    self.assertFalse(callbacks)
                finally:
                    release.set()
                    self.until(lambda: not view.busy)
                self.assertEqual(callbacks, [(main, self.result)])
                self.assertNotEqual(workers, [main])
                self.assertEqual(busy, [True, False])
                self.assertEqual(view.status.cget("text"), t("pairing.connected"))
                self.assertEqual(view.code_var.get(), "")

        def test_failure_never_exposes_network_details_and_retry_works(self):
            with patch.object(helper_pairing, "pair_helper", side_effect=RuntimeError(_CODE + _TOKEN)) as pair:
                _, view = self.view()
                view.connect_button.invoke()
                self.until(lambda: not view.busy)
                self.assertEqual(view.status.cget("text"), t("pairing.error"))
                self.assertEqual(view.code_var.get(), "")
                pair.side_effect = None
                pair.return_value = self.result
                view.code_var.set(_CODE)
                view.connect_button.invoke()
                self.until(lambda: not view.busy)
                self.assertEqual(view.status.cget("text"), t("pairing.connected"))

        def test_cancel_and_destroy_signal_worker_and_prevent_late_callbacks(self):
            for destroy in (False, True):
                with self.subTest(destroy=destroy):
                    entered, finished = threading.Event(), threading.Event()
                    callback = Mock()

                    def wait_cancel(*args, cancel_event):
                        entered.set()
                        cancel_event.wait(2)
                        finished.set()
                        raise PairingCancelled("Pairing cancelled")

                    with patch.object(helper_pairing, "pair_helper", side_effect=wait_cancel):
                        window, view = self.view(callback=callback)
                        view.connect_button.invoke()
                        self.assertTrue(entered.wait(1))
                        if destroy:
                            window.destroy()
                            self.assertTrue(view.task.closed)
                            self.assertIsNone(view.task.pending)
                            self.assertFalse(view.busy)
                        else:
                            view.cancel_button.invoke()
                            self.until(lambda: not view.busy)
                            self.assertEqual(view.status.cget("text"), t("pairing.cancelled"))
                        self.assertTrue(finished.wait(1))
                        self.pump(100)
                        callback.assert_not_called()
                        self.assertEqual(view.code_var.get(), "")

        def test_form_success_fills_secure_fields_without_persisting_configuration(self):
            from ui.helper_form import HelperForm
            from utils.helper_registry import HelperLease
            original = {"helper_enabled": True, "helper_mode": "legacy", "helper_host": "127.0.0.1", "helper_port": 8443}
            window = self.ctk.CTkToplevel(self.app)
            window.withdraw()
            self.windows.append(window)
            form = HelperForm(self.ctk, window, self.theme, original)
            form.section.pack(fill="both", expand=True)
            self.assertFalse(form._advanced_expanded)
            self.assertEqual(form.advanced.winfo_manager(), "")
            form.advanced_button.invoke()
            self.assertTrue(form._advanced_expanded)
            self.assertEqual(form.advanced.winfo_manager(), "pack")
            self.assertIsNone(form.pairing.code_entry)
            lease = HelperLease("127.0.0.1", 18444, "a" * 64, _TOKEN, 2000000000)
            with patch.object(helper_pairing, "discover_helper", return_value=lease):
                form.pairing.connect()
                self.until(lambda: not form.pairing.busy)
            self.assertTrue(form.enabled.get())
            self.assertFalse(form.busy_var.get())
            self.assertEqual((form.mode.get(), form.host.get(), form.port.get(), form.fingerprint.get(), form.token.get()),
                             ("tls-pin", "127.0.0.1", "18444", "a" * 64, ""))
            self.assertTrue(form.registry.get())
            self.assertEqual(original["helper_mode"], "legacy")
            self.assertNotIn("helper_token_dpapi", original)

        def test_pairing_blocks_form_and_ssh_until_cancel_completes(self):
            from ui.helper_form import HelperForm
            window = self.ctk.CTkToplevel(self.app)
            window.withdraw()
            self.windows.append(window)
            form = HelperForm(self.ctk, window, self.theme,
                              {"helper_enabled": True, "helper_host": "127.0.0.1"})
            form.section.pack(fill="both", expand=True)
            entered = threading.Event()

            def wait_cancel(*args, cancel_event, force=False):
                entered.set()
                cancel_event.wait(2)
                raise PairingCancelled("Pairing cancelled")

            with patch.object(helper_pairing, "discover_helper", side_effect=wait_cancel):
                form.pairing.connect()
                self.assertTrue(entered.wait(1))
                self.assertTrue(form.busy_var.get())
                controls = (form.toggle, form.mode_menu, *form.address_entries, *form.tls_entries,
                            form.ssh_setup.header_button, form.ssh_setup.install_button)
                for control in controls:
                    self.assertEqual(control.cget("state"), "disabled")
                form.pairing.cancel()
                self.until(lambda: not form.pairing.busy)
                self.assertFalse(form.busy_var.get())
                for control in controls:
                    self.assertEqual(control.cget("state"), "normal")
                self.assertEqual(form.token.get(), "")


if __name__ == "__main__":
    if _NATIVE_MODE:
        sys.argv.remove("--native-run")
    unittest.main()
