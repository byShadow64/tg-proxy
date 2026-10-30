"""Native SSH setup UI tests; every network/deployment adapter is mocked."""
import logging
import subprocess
import sys
import threading
import time
import unittest
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tkinter import TclError

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ui import ssh_setup
from ui.ctk_theme import apply_ctk_appearance, ctk_theme_for_platform
from ui.i18n import get_config_language, set_language, t

_NATIVE_MODE = "--native-run" in sys.argv
_PASSWORD = "synthetic-ssh-password-not-a-real-credential"
_TOKEN = "synthetic-helper-token-not-a-real-credential"


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


if not _NATIVE_MODE:
    class SSHSetupProcessTest(unittest.TestCase):
        def test_native_ssh_setup_scenarios(self):
            # CTk font and image caches belong to one Tcl interpreter. Avoid
            # interacting with app roots from other native test modules.
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--native-run"],
                capture_output=True, text=True, timeout=40,
            )
            if "NATIVE_DISPLAY_UNAVAILABLE" in result.stdout:
                self.skipTest("Native Tk display is unavailable")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if _NATIVE_MODE:
    class NativeSSHSetupTest(unittest.TestCase):
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
            self.windows, self.errors, self.messages = [], [], []
            self.app.report_callback_exception = lambda *args: self.errors.append(args)
            self.addCleanup(set_language, get_config_language())
            self.addCleanup(self.ctk.set_appearance_mode, self.ctk.get_appearance_mode())
            set_language("en")
            apply_ctk_appearance(self.ctk, "light")
            self.theme = ctk_theme_for_platform()
            self.key = SimpleNamespace(key_type="ssh-ed25519", fingerprint="SHA256:synthetic-server-key")
            self.result = SimpleNamespace(
                host="203.0.113.10", port=8444, tls_fingerprint="ab" * 32, token=_TOKEN,
            )
            self.stack = ExitStack()
            self.addCleanup(self.stack.close)
            self.probe = self.stack.enter_context(mock.patch.object(
                ssh_setup, "_probe_server", return_value=self.key,
            ))
            self.deploy = self.stack.enter_context(mock.patch.object(
                ssh_setup, "_install_server", return_value=self.result,
            ))
            self.confirm = self.stack.enter_context(mock.patch.object(
                ssh_setup.messagebox, "askyesno", return_value=True,
            ))
            handler = logging.Handler()
            handler.emit = lambda record: self.messages.append(record.getMessage())
            ssh_setup.log.addHandler(handler)
            self.addCleanup(ssh_setup.log.removeHandler, handler)

        def tearDown(self):
            for window in self.windows:
                if window.winfo_exists():
                    window.destroy()
            self.app.update()
            self.assertFalse(self.errors)
            self.assertNotIn(_PASSWORD, "\n".join(self.messages))
            self.assertNotIn(_TOKEN, "\n".join(self.messages))

        def pump(self, milliseconds=20):
            ready = self.ctk.BooleanVar(master=self.app, value=False)
            self.app.after(milliseconds, lambda: ready.set(True))
            self.app.wait_variable(ready)
            self.app.update()

        def until(self, predicate, timeout=3):
            deadline = time.monotonic() + timeout
            while not predicate():
                if time.monotonic() >= deadline:
                    self.fail("SSH setup did not reach the expected UI state")
                self.pump()
            self.app.update_idletasks()

        def view(self, *, callback=None, busy_callback=None, host_var=None):
            window = self.ctk.CTkToplevel(self.app)
            window.withdraw()
            self.windows.append(window)
            container = self.ctk.CTkFrame(window, fg_color="transparent")
            container.pack(fill="both", expand=True, padx=28, pady=24)
            footer = self.ctk.CTkFrame(container, fg_color="transparent")
            footer.pack(side="bottom", fill="x", pady=(16, 0))
            for text in (t("button.save"), t("button.cancel")):
                self.ctk.CTkButton(footer, text=text, height=40, command=lambda: None).pack(
                    side="left", fill="x", expand=True, padx=4,
                )
            scroll = self.ctk.CTkScrollableFrame(container, fg_color="transparent", corner_radius=0)
            scroll.pack(fill="both", expand=True)
            callback = callback if callback is not None else mock.Mock()
            busy_callback = busy_callback if busy_callback is not None else mock.Mock()
            view = ssh_setup.SSHSetup(
                self.ctk, scroll, self.theme, on_installed=callback,
                on_busy=busy_callback, host_var=host_var,
            )
            view.frame.pack(fill="x")
            window.geometry("560x560+12000+12000")
            window.deiconify()
            self.pump(60)
            return window, view, scroll, footer, callback, busy_callback

        def credentials(self, view):
            view.header_button.invoke()
            view.host_var.set("203.0.113.10")
            view.password_var.set(_PASSWORD)
            self.pump()

        def visible_text(self, root):
            return "\n".join(
                widget.cget("text") for widget in descendants(root)
                if isinstance(widget, (self.ctk.CTkLabel, self.ctk.CTkButton))
            )

        def assertPrivate(self, root):
            text = self.visible_text(root)
            self.assertNotIn(_PASSWORD, text)
            self.assertNotIn(_TOKEN, text)

        def assertInside(self, widget, container):
            self.assertTrue(widget.winfo_ismapped())
            x = widget.winfo_rootx() - container.winfo_rootx()
            y = widget.winfo_rooty() - container.winfo_rooty()
            self.assertGreaterEqual(x, -1)
            self.assertGreaterEqual(y, -1)
            self.assertLessEqual(x + widget.winfo_width(), container.winfo_width() + 1)
            self.assertLessEqual(y + widget.winfo_height(), container.winfo_height() + 1)

        def test_defaults_collapse_and_local_validation_do_not_contact_a_server(self):
            shared = self.ctk.StringVar(master=self.app, value="203.0.113.20")
            _, view, _, _, installed, _ = self.view(host_var=shared)
            self.assertIs(view.host_var, shared)
            self.assertEqual(view.port_var.get(), "22")
            self.assertEqual(view.user_var.get(), "root")
            self.assertEqual(view.password_var.get(), "")
            self.assertFalse(view.details.winfo_viewable())

            view.header_button.invoke()
            self.pump()
            self.assertTrue(view.details.winfo_viewable())
            view.host_var.set("")
            view.install_button.invoke()
            self.assertEqual(view.status.cget("text"), t("ssh.invalid_host"))
            view.host_var.set("203.0.113.10")
            view.port_var.set("70000")
            view.install_button.invoke()
            self.assertEqual(view.status.cget("text"), t("validation.bad_port"))
            view.port_var.set("22")
            view.install_button.invoke()
            self.assertEqual(view.status.cget("text"), t("ssh.credentials_required"))
            self.assertFalse(view.busy)
            self.probe.assert_not_called()
            self.deploy.assert_not_called()
            installed.assert_not_called()

        def test_existing_private_upgrade_requires_separate_target_bound_consent(self):
            _, view, _, _, _, _ = self.view()
            self.credentials(view)
            view.registry_var.set(True)
            self.assertEqual(view.private_upgrade_frame.winfo_manager(), "pack")
            self.assertFalse(view.private_upgrade_var.get())
            view.private_upgrade_var.set(True)
            view.host_var.set("203.0.113.11")
            self.assertFalse(view.private_upgrade_var.get())
            view.private_upgrade_var.set(True)
            view.registry_var.set(False)
            self.assertFalse(view.private_upgrade_var.get())
            self.assertEqual(view.private_upgrade_frame.winfo_manager(), "")
            view.registry_var.set(True)
            self.assertFalse(view.private_upgrade_var.get())

        def test_confirmed_key_is_pinned_and_both_phases_keep_the_ui_responsive(self):
            main_thread = threading.get_ident()
            probe_entered, probe_release = threading.Event(), threading.Event()
            deploy_entered, deploy_release = threading.Event(), threading.Event()
            worker_threads, callback_threads, busy_values = [], [], []

            def probe(host, port, user):
                worker_threads.append(threading.get_ident())
                probe_entered.set()
                probe_release.wait(3)
                return self.key

            def confirm(*args, **kwargs):
                callback_threads.append(threading.get_ident())
                self.deploy.assert_not_called()
                self.assertIn(self.key.fingerprint, args[1])
                self.assertIn(self.key.key_type, args[1])
                self.assertIn("203.0.113.10:22", args[1])
                self.assertNotIn(_PASSWORD, args[1])
                self.assertEqual(kwargs["default"], "no")
                return True

            def deploy(host, port, user, password, key, progress):
                worker_threads.append(threading.get_ident())
                self.assertIs(key, self.key)
                self.assertEqual((host, port, user, password), ("203.0.113.10", 22, "root", _PASSWORD))
                progress("upload")
                deploy_entered.set()
                deploy_release.wait(3)
                progress("install")
                progress("verify_result")
                return self.result

            installed = mock.Mock(side_effect=lambda result: callback_threads.append(threading.get_ident()))
            _, view, _, _, _, _ = self.view(
                callback=installed, busy_callback=lambda value: busy_values.append(value),
            )
            self.credentials(view)
            self.probe.side_effect, self.deploy.side_effect, self.confirm.side_effect = probe, deploy, confirm
            try:
                view.install_button.invoke()
                self.assertTrue(probe_entered.wait(2))
                self.assertTrue(view.busy)
                self.assertEqual(view.install_button.cget("state"), "disabled")
                self.assertEqual(view.password_entry.cget("state"), "disabled")
                self.assertTrue(view.password_entry.cget("show"))
                view.install_button.invoke()
                view.install()
                heartbeat = []
                self.app.after(0, lambda: heartbeat.append(True))
                self.pump(60)
                self.assertEqual(heartbeat, [True])
                self.probe.assert_called_once_with("203.0.113.10", 22, "root")
                self.confirm.assert_not_called()
                self.deploy.assert_not_called()
                probe_release.set()
                self.until(deploy_entered.is_set)
                self.assertTrue(view.busy)
                self.until(lambda: view.status.cget("text") == t("ssh.stage.upload"))
                view.install()
                self.assertEqual(self.probe.call_count, 1)
                self.assertEqual(self.deploy.call_count, 1)
                installed.assert_not_called()
            finally:
                probe_release.set()
                deploy_release.set()
                self.until(lambda: not view.busy)
            installed.assert_called_once_with(self.result)
            self.assertTrue(all(identifier != main_thread for identifier in worker_threads))
            self.assertEqual(callback_threads, [main_thread, main_thread])
            self.assertEqual(busy_values, [True, False])
            self.assertEqual(view.password_var.get(), "")
            self.assertEqual(view.status.cget("text"), t("ssh.installed"))
            self.assertEqual(view.install_button.cget("state"), "normal")

        def test_declining_the_default_no_host_key_prompt_cancels_before_deployment(self):
            window, view, _, _, installed, _ = self.view()
            self.credentials(view)
            self.confirm.return_value = False
            view.install_button.invoke()
            self.until(lambda: not view.busy)
            self.confirm.assert_called_once()
            self.assertEqual(self.confirm.call_args.kwargs["default"], "no")
            self.deploy.assert_not_called()
            installed.assert_not_called()
            self.assertEqual(view.password_var.get(), "")
            self.assertEqual(view.status.cget("text"), t("ssh.cancelled"))
            self.assertPrivate(window)

        def test_probe_or_deployment_failure_is_generic_and_retry_is_possible(self):
            window, view, _, _, installed, _ = self.view()
            self.credentials(view)
            for phase in ("probe", "deploy"):
                with self.subTest(phase=phase):
                    self.probe.side_effect = None
                    self.deploy.side_effect = None
                    failing = self.probe if phase == "probe" else self.deploy
                    failing.side_effect = RuntimeError(f"Untrusted detail {_PASSWORD} {_TOKEN}")
                    view.password_var.set(_PASSWORD)
                    view.install_button.invoke()
                    self.until(lambda: not view.busy)
                    self.assertEqual(view.status.cget("text"), t("ssh.error"))
                    self.assertEqual(view.password_var.get(), "")
                    self.assertEqual(view.install_button.cget("state"), "normal")
                    installed.assert_not_called()
                    self.assertPrivate(window)
            self.probe.side_effect = self.deploy.side_effect = None
            view.password_var.set(_PASSWORD)
            view.install_button.invoke()
            self.until(lambda: not view.busy)
            installed.assert_called_once_with(self.result)
            self.assertEqual(view.status.cget("text"), t("ssh.installed"))
            self.assertEqual(view.password_var.get(), "")
            self.assertPrivate(window)

        def test_destroy_during_either_phase_clears_password_and_cancels_ui_callbacks(self):
            for phase in ("probe", "deploy"):
                with self.subTest(phase=phase):
                    self.probe.side_effect = self.deploy.side_effect = None
                    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

                    def block(*args):
                        entered.set()
                        try:
                            release.wait(3)
                            return self.key if phase == "probe" else self.result
                        finally:
                            finished.set()

                    target = self.probe if phase == "probe" else self.deploy
                    target.side_effect = block
                    window, view, _, _, installed, _ = self.view()
                    self.credentials(view)
                    try:
                        view.install_button.invoke()
                        self.until(entered.is_set)
                        self.assertTrue(view.busy)
                        window.destroy()
                        self.assertEqual(view.password_var.get(), "")
                        self.assertFalse(view.busy)
                        self.assertTrue(view.task.closed)
                        self.assertIsNone(view.task.pending)
                    finally:
                        release.set()
                        self.assertTrue(finished.wait(2))
                        self.pump(150)
                    view.install()
                    view.refresh()
                    installed.assert_not_called()
                    self.assertFalse(self.errors)

        def test_inline_expansion_and_install_footer_fit_minimum_size_in_both_languages(self):
            for language in ("ru", "en"):
                for appearance in ("light", "dark"):
                    with self.subTest(language=language, appearance=appearance):
                        set_language(language)
                        apply_ctk_appearance(self.ctk, appearance)
                        window, view, scroll, footer, _, _ = self.view()
                        count = len([child for child in self.app.winfo_children()
                                     if isinstance(child, self.ctk.CTkToplevel)])
                        view.header_button.invoke()
                        self.pump()
                        self.assertTrue(view.details.winfo_viewable())
                        self.assertEqual(view.password_var.get(), "")
                        self.assertTrue(view.password_entry.cget("show"))
                        self.assertNotIn("ssh.", self.visible_text(view.frame))
                        self.assertEqual(count, len([child for child in self.app.winfo_children()
                                                   if isinstance(child, self.ctk.CTkToplevel)]))
                        position = view.install_button.winfo_rooty() - scroll.winfo_rooty()
                        scroll._parent_canvas.yview_moveto(max(0, (position - 12) / scroll.winfo_height()))
                        self.pump()
                        self.assertInside(view.install_button, scroll._parent_canvas)
                        self.assertInside(view.install_button._text_label, view.install_button)
                        for child in descendants(footer):
                            if isinstance(child, self.ctk.CTkButton):
                                self.assertInside(child, window)
                        self.assertPrivate(window)
                        window.destroy()
            self.probe.assert_not_called()
            self.deploy.assert_not_called()

        def test_parent_helper_fields_and_settings_save_cancel_are_guarded_until_install_finishes(self):
            from ui import settings_dialog
            from ui.ctk_tray_ui import install_tray_config_buttons
            from ui.helper_form import HelperForm

            window = self.ctk.CTkToplevel(self.app)
            window.withdraw()
            self.windows.append(window)
            container = self.ctk.CTkFrame(window, fg_color="transparent")
            container.pack(fill="both", expand=True, padx=28, pady=24)
            footer = self.ctk.CTkFrame(container, fg_color="transparent")
            footer.pack(side="bottom", fill="x")
            scroll = self.ctk.CTkScrollableFrame(container, fg_color="transparent")
            scroll.pack(fill="both", expand=True)
            config = {
                "helper_enabled": True, "helper_mode": "legacy",
                "helper_host": "203.0.113.10", "helper_port": 8443,
                "helper_fingerprint": "cd" * 32, "helper_token_dpapi": "synthetic-old-cipher",
            }
            before = deepcopy(config)
            helper = HelperForm(self.ctk, scroll, self.theme, config)
            persist, finish = mock.Mock(), mock.Mock()
            dialog = settings_dialog.SettingsDialog(
                ctk=self.ctk, root=window, widgets=SimpleNamespace(helper_busy_var=helper.busy_var),
                config={}, defaults={}, persist=persist, refresh_menu=mock.Mock(),
                finish=finish, restart=mock.Mock(),
            )
            install_tray_config_buttons(
                self.ctk, footer, self.theme, on_save=dialog.save, on_cancel=dialog.cancel,
                busy_var=helper.busy_var,
            )
            window.geometry("560x560+12000+12000")
            window.deiconify()
            self.pump(60)
            view = helper.ssh_setup
            self.credentials(view)
            entered, release = threading.Event(), threading.Event()

            def deploy(*args):
                entered.set()
                release.wait(3)
                return self.result

            self.deploy.side_effect = deploy
            with mock.patch.object(settings_dialog.messagebox, "showinfo") as information:
                try:
                    view.install_button.invoke()
                    self.until(entered.is_set)
                    self.assertTrue(helper.busy_var.get())
                    for control in (helper.toggle, helper.mode_menu, *helper.address_entries,
                                    *helper.tls_entries):
                        self.assertEqual(control.cget("state"), "disabled")
                    for button in descendants(footer):
                        if isinstance(button, self.ctk.CTkButton):
                            self.assertEqual(button.cget("state"), "disabled")
                    dialog.save()
                    dialog.cancel()
                    persist.assert_not_called()
                    finish.assert_not_called()
                    self.assertEqual(information.call_count, 2)
                    self.assertFalse(dialog.closed)
                finally:
                    release.set()
                    self.until(lambda: not view.busy)
            self.assertFalse(helper.busy_var.get())
            self.assertTrue(helper.enabled.get())
            self.assertEqual(helper.mode.get(), "tls-pin")
            self.assertEqual(helper.host.get(), self.result.host)
            self.assertEqual(helper.port.get(), str(self.result.port))
            self.assertEqual(helper.fingerprint.get(), self.result.tls_fingerprint)
            self.assertEqual(helper.token.get(), self.result.token)
            self.assertTrue(helper.tls_entries[-1].cget("show"))
            self.assertEqual(view.password_var.get(), "")
            self.assertEqual(config, before)
            for control in (helper.toggle, helper.mode_menu, *helper.address_entries, *helper.tls_entries):
                self.assertEqual(control.cget("state"), "normal")
            for button in descendants(footer):
                if isinstance(button, self.ctk.CTkButton):
                    self.assertEqual(button.cget("state"), "normal")
            self.assertPrivate(window)


if __name__ == "__main__":
    if _NATIVE_MODE:
        sys.argv.remove("--native-run")
    unittest.main()
