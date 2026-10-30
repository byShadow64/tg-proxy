"""Native settings switch regression with synthetic helper credentials only."""
import base64
import re
import subprocess
import sys
import unittest
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from unittest import mock

from tkinter import TclError

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ui import helper_settings, settings_dialog, settings_form
from ui.ctk_theme import apply_ctk_appearance, ctk_theme_for_platform, main_content_frame
from ui.ctk_tray_ui import install_tray_config_buttons, tray_settings_scroll_and_footer
from ui.i18n import get_config_language, set_language, t
from utils import secure_storage
from utils.default_config import default_tray_config

_NATIVE_MODE = "--native-run" in sys.argv
_HELPER_FIELDS = (
    "helper_mode", "helper_host", "helper_port", "helper_fingerprint", "helper_token_dpapi",
)


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


if not _NATIVE_MODE:
    class HelperSettingsToggleProcessTest(unittest.TestCase):
        def test_native_helper_settings_switch_scenarios(self):
            # Use one separate Tcl interpreter for this suite: CTk keeps fonts
            # and image caches tied to its first app root in a process.
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--native-run"],
                capture_output=True, text=True, timeout=60,
            )
            if "NATIVE_DISPLAY_UNAVAILABLE" in result.stdout:
                self.skipTest("Native Tk display is unavailable")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if _NATIVE_MODE:
    class NativeHelperSettingsToggleTest(unittest.TestCase):
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
            self.windows = []
            self.errors = []
            self.app.report_callback_exception = lambda *args: self.errors.append(args)
            self.addCleanup(set_language, get_config_language())
            self.addCleanup(self.ctk.set_appearance_mode, self.ctk.get_appearance_mode())
            set_language("en")
            apply_ctk_appearance(self.ctk, "light")
            self.theme = ctk_theme_for_platform()
            self.stack = ExitStack()
            self.addCleanup(self.stack.close)
            self.network = []
            for name in ("run_check", "run_cfproxy_multi_test", "run_cfproxy_auto_test",
                         "run_cfworker_multi_test"):
                self.network.append(self.stack.enter_context(mock.patch.object(
                    settings_form, name, side_effect=AssertionError("Real network is forbidden"),
                )))
            self.show_error = self.stack.enter_context(mock.patch.object(
                settings_dialog.messagebox, "showerror",
            ))
            self.ask_restart = self.stack.enter_context(mock.patch.object(
                settings_dialog.messagebox, "askyesno", return_value=False,
            ))
            self.dpapi = self.stack.enter_context(mock.patch.object(
                secure_storage, "_dpapi", return_value=b"synthetic-protected-inline-token",
            ))

        def tearDown(self):
            for window in self.windows:
                if window.winfo_exists():
                    window.destroy()
            self.app.update()
            for network in self.network:
                network.assert_not_called()
            self.assertFalse(self.errors)

        def pump(self, milliseconds=40):
            ready = self.ctk.BooleanVar(master=self.app, value=False)
            self.app.after(milliseconds, lambda: ready.set(True))
            self.app.wait_variable(ready)
            self.app.update()

        def configured(self, mode="tls-pin", enabled=None):
            config = default_tray_config()
            config.update(
                language="en", helper_mode=mode, helper_host="203.0.113.10",
                helper_port=8443 if mode == "legacy" else 8444,
                helper_fingerprint="a1" * 32,
                helper_token_dpapi="synthetic-protected-token-not-a-user-secret",
            )
            if enabled is None:
                config.pop("helper_enabled", None)
            else:
                config["helper_enabled"] = enabled
            return config

        def form(self, config, *, language="en", appearance="light"):
            set_language(language)
            apply_ctk_appearance(self.ctk, appearance)
            config["language"] = language
            window = self.ctk.CTkToplevel(self.app)
            window.withdraw()
            self.windows.append(window)
            frame = main_content_frame(self.ctk, window, self.theme, padx=28, pady=24)
            content, footer = tray_settings_scroll_and_footer(self.ctk, frame, self.theme)
            widgets = settings_form.install_tray_config_form(
                self.ctk, content, self.theme, config, default_tray_config(),
            )
            install_tray_config_buttons(
                self.ctk, footer, self.theme, on_save=lambda: None, on_cancel=lambda: None,
            )
            window.geometry("560x560+12000+12000")
            window.deiconify()
            navigation = next(widget for widget in descendants(content)
                              if isinstance(widget, self.ctk.CTkSegmentedButton))
            navigation.set(t("settings.tab.routes"))
            navigation.cget("command")(t("settings.tab.routes"))
            self.pump(60)
            switch = next(widget for widget in descendants(content)
                          if isinstance(widget, self.ctk.CTkSwitch)
                          and widget.cget("variable") is widgets.helper_enabled_var)
            route = next(widget for widget in descendants(content)
                         if isinstance(widget, self.ctk.CTkScrollableFrame)
                         and switch in tuple(descendants(widget)))
            route._parent_canvas.yview_moveto(0)
            self.pump()
            return window, widgets, switch, route, footer

        def validate(self, widgets):
            return settings_form.validate_config_form(
                widgets, default_tray_config(), include_autostart=False,
            )

        def helper_form(self, config):
            window = self.ctk.CTkToplevel(self.app)
            window.withdraw()
            self.windows.append(window)
            save, restart, refreshed = mock.Mock(), mock.Mock(), mock.Mock()
            helper_settings.build_helper_settings(
                self.ctk, window, self.theme, config, save_config=save,
                restart=restart, on_saved=refreshed,
            )
            window.geometry("560x560+12000+12000")
            window.deiconify()
            self.pump(60)
            mode = next(widget for widget in descendants(window)
                        if isinstance(widget, self.ctk.CTkOptionMenu))
            fields = {widget.cget("placeholder_text"): widget.cget("textvariable")
                      for widget in descendants(window)
                      if isinstance(widget, self.ctk.CTkEntry)}
            submit = next(widget for widget in descendants(window)
                          if isinstance(widget, self.ctk.CTkButton)
                          and widget.cget("text") == t("helper.save_restart"))
            return window, mode, fields, submit, save, restart, refreshed

        def save(self, config, window, widgets):
            persist, restart, finish = mock.Mock(), mock.Mock(), mock.Mock()
            dialog = settings_dialog.SettingsDialog(
                ctk=self.ctk, root=window, widgets=widgets, config=config,
                defaults=default_tray_config(), persist=persist,
                refresh_menu=mock.Mock(), finish=finish, restart=restart,
            )
            dialog.save()
            persist.assert_called_once()
            finish.assert_called_once_with()
            restart.assert_not_called()
            self.show_error.assert_not_called()
            return deepcopy(persist.call_args.args[0])

        def assertInside(self, widget, parent):
            self.assertTrue(widget.winfo_ismapped())
            x = widget.winfo_rootx() - parent.winfo_rootx()
            y = widget.winfo_rooty() - parent.winfo_rooty()
            self.assertGreaterEqual(x, -1)
            self.assertGreaterEqual(y, -1)
            self.assertLessEqual(x + widget.winfo_width(), parent.winfo_width() + 1)
            self.assertLessEqual(y + widget.winfo_height(), parent.winfo_height() + 1)

        def test_legacy_configs_infer_the_switch_and_explicit_false_takes_precedence(self):
            for mode, explicit, expected in (
                ("tls-pin", None, True), ("legacy", None, True),
                ("direct", None, False),
            ):
                with self.subTest(mode=mode, explicit=explicit):
                    config = self.configured(mode, explicit)
                    window, widgets, switch, _, _ = self.form(config)
                    self.assertEqual(widgets.helper_enabled_var.get(), expected)
                    self.assertEqual(bool(switch.get()), expected)
                    self.assertIsNot(widgets.helper_config, config)
                    for key in _HELPER_FIELDS:
                        self.assertEqual(widgets.helper_config[key], config[key])
                    window.destroy()

        def test_focus_decoration_accepts_native_callbacks_without_event_during_close(self):
            window, widgets, _, route, _ = self.form(self.configured(enabled=False))
            entry = next(widget for widget in descendants(window)
                         if isinstance(widget, self.ctk.CTkEntry)
                         and widget.cget("textvariable") is widgets.host_var)
            for sequence, expected in (("<FocusIn>", self.theme.accent),
                                       ("<FocusOut>", self.theme.field_border)):
                script = entry._entry.bind(sequence)
                commands = re.findall(r"\[([^\s]+) %#", script)
                self.assertGreaterEqual(len(commands), 2, script)
                # Use the actual Tcl-registered project handler (the last one,
                # after CTk's own binding), with the no-event call observed in
                # native teardown; no callback exceptions may be suppressed by
                # the test's strict report_callback_exception collector.
                entry.tk.call(commands[-1])
                self.assertEqual(entry.cget("border_color"), expected)
            window.destroy()
            self.pump()
            self.assertFalse(self.errors)

        def test_off_save_reopen_and_on_save_keep_transport_and_credentials(self):
            for mode in ("tls-pin", "legacy"):
                with self.subTest(mode=mode):
                    config = self.configured(mode)
                    retained = {key: config[key] for key in _HELPER_FIELDS}
                    window, widgets, switch, _, _ = self.form(config)
                    switch.toggle()
                    self.assertFalse(widgets.helper_enabled_var.get())
                    self.assertFalse(self.validate(widgets)["helper_enabled"])
                    disabled = self.save(config, window, widgets)
                    self.assertIs(disabled["helper_enabled"], False)
                    self.assertEqual({key: disabled[key] for key in _HELPER_FIELDS}, retained)
                    window.destroy()

                    reopened, form, switch, _, _ = self.form(disabled)
                    self.assertFalse(form.helper_enabled_var.get())
                    self.assertEqual(form.helper_token_var.get(), "")
                    form.helper_token_var.set("   ")
                    switch.toggle()
                    self.assertTrue(self.validate(form)["helper_enabled"])
                    enabled = self.save(disabled, reopened, form)
                    self.assertIs(enabled["helper_enabled"], True)
                    self.assertEqual({key: enabled[key] for key in _HELPER_FIELDS}, retained)
                    reopened.destroy()
            self.dpapi.assert_not_called()

        def test_fresh_inline_tls_profile_is_saved_with_a_protected_new_token(self):
            config = default_tray_config()
            window, widgets, switch, _, _ = self.form(config)
            switch.toggle()
            widgets.helper_mode_var.set("tls-pin")
            widgets.helper_host_var.set("203.0.113.20")
            widgets.helper_port_var.set("9444")
            widgets.helper_fingerprint_var.set("\t" + ":".join(["AB"] * 32) + "\r\n")
            widgets.helper_token_var.set("new-inline-helper-token")
            self.assertEqual(config["helper_host"], "")
            saved = self.save(config, window, widgets)
            self.assertTrue(saved["helper_enabled"])
            self.assertEqual(saved["helper_mode"], "tls-pin")
            self.assertEqual(saved["helper_host"], "203.0.113.20")
            self.assertEqual(saved["helper_port"], 9444)
            self.assertEqual(saved["helper_fingerprint"], "ab" * 32)
            self.dpapi.assert_called_once_with(True, b"new-inline-helper-token")
            self.assertEqual(saved["helper_token_dpapi"],
                             base64.b64encode(b"synthetic-protected-inline-token").decode("ascii"))
            self.assertNotIn("new-inline-helper-token", repr(saved))

        def test_enabling_configured_direct_profile_selects_tls_without_losing_access_data(self):
            config = self.configured("direct", False)
            retained = {key: config[key] for key in _HELPER_FIELDS if key != "helper_mode"}
            window, widgets, switch, _, _ = self.form(config)
            switch.toggle()
            values = self.validate(widgets)
            self.assertTrue(values["helper_enabled"])
            self.assertEqual(values["helper_mode"], "tls-pin")
            saved = self.save(config, window, widgets)
            self.assertEqual(saved["helper_mode"], "tls-pin")
            self.assertEqual({key: saved[key] for key in retained}, retained)

        def test_enabled_tls_requires_host_valid_port_fingerprint_and_protected_token(self):
            config = self.configured(enabled=False)
            config["helper_token_dpapi"] = ""
            _, widgets, switch, _, _ = self.form(config)
            before = deepcopy(config)
            switch.toggle()
            widgets.helper_token_var.set("new-token")
            invalid = (
                ("helper_host_var", "", "helper.host_required"),
                ("helper_port_var", "0", "validation.bad_port"),
                ("helper_fingerprint_var", "a" * 63, "helper.bad_fingerprint"),
                ("helper_token_var", "", "helper.token_required"),
            )
            for key, value, error_key in invalid:
                with self.subTest(key=key, value=value):
                    variable = getattr(widgets, key)
                    previous = variable.get()
                    variable.set(value)
                    result = self.validate(widgets)
                    self.assertEqual(result, t(error_key))
                    self.assertNotEqual(result, error_key)
                    self.assertEqual(config, before)
                    self.dpapi.assert_not_called()
                    variable.set(previous)
            # A helper token must also remain unprotected while another part
            # of the same settings form fails validation.
            widgets.port_var.set("not-a-port")
            self.assertEqual(self.validate(widgets), t("validation.bad_port"))
            self.dpapi.assert_not_called()
            self.assertEqual(config, before)

        def test_unconfigured_or_incomplete_legacy_helper_cannot_be_enabled(self):
            configs = [default_tray_config()]
            for key, value in (("helper_host", ""),):
                config = self.configured("legacy", False)
                config[key] = value
                configs.append(config)
            for index, config in enumerate(configs):
                with self.subTest(profile=index):
                    before = deepcopy(config)
                    window, widgets, switch, _, _ = self.form(config)
                    switch.toggle()
                    persist, finish = mock.Mock(), mock.Mock()
                    dialog = settings_dialog.SettingsDialog(
                        ctk=self.ctk, root=window, widgets=widgets, config=config,
                        defaults=default_tray_config(), persist=persist,
                        refresh_menu=mock.Mock(), finish=finish, restart=mock.Mock(),
                    )
                    dialog.save()
                    persist.assert_not_called()
                    finish.assert_not_called()
                    self.assertFalse(dialog.closed)
                    self.assertEqual(self.show_error.call_args.args[1], t("helper.host_required"))
                    # The form picks a display language; failed Save must keep
                    # the existing helper fields and its enabled state intact.
                    for key in _HELPER_FIELDS + ("helper_enabled",):
                        self.assertEqual(config.get(key), before.get(key))
                    window.destroy()

        def test_disabling_invalid_profile_is_allowed_and_keeps_access_data(self):
            config = self.configured(enabled=True)
            retained = {key: config[key] for key in _HELPER_FIELDS}
            window, widgets, switch, _, _ = self.form(config)
            widgets.helper_host_var.set("unsaved.example.invalid")
            widgets.helper_port_var.set("not-a-port")
            widgets.helper_fingerprint_var.set("not-a-fingerprint")
            widgets.helper_token_var.set("unsaved-token")
            switch.toggle()
            saved = self.save(config, window, widgets)
            self.assertFalse(saved["helper_enabled"])
            self.assertEqual({key: saved[key] for key in _HELPER_FIELDS}, retained)
            self.dpapi.assert_not_called()

        def test_inline_fields_reappear_with_edits_and_cancel_keeps_stored_credentials(self):
            config = self.configured(enabled=False)
            window, widgets, switch, _, _ = self.form(config)
            before = deepcopy(config)
            self.assertFalse(widgets.helper_fields.winfo_viewable())
            switch.toggle()
            self.pump()
            self.assertTrue(widgets.helper_fields.winfo_viewable())
            edits = {
                "helper_host_var": "203.0.113.20", "helper_port_var": "9444",
                "helper_fingerprint_var": "cd" * 32, "helper_token_var": "unsaved-token",
            }
            for key, value in edits.items():
                getattr(widgets, key).set(value)
            switch.toggle()
            self.pump()
            self.assertFalse(widgets.helper_fields.winfo_viewable())
            switch.toggle()
            self.pump()
            self.assertTrue(widgets.helper_fields.winfo_viewable())
            for key, value in edits.items():
                self.assertEqual(getattr(widgets, key).get(), value)
            persist = mock.Mock()
            dialog = settings_dialog.SettingsDialog(
                ctk=self.ctk, root=window, widgets=widgets, config=config,
                defaults=default_tray_config(), persist=persist,
                refresh_menu=mock.Mock(), finish=mock.Mock(), restart=mock.Mock(),
            )
            dialog.cancel()
            persist.assert_not_called()
            self.assertEqual(config, before)
            self.dpapi.assert_not_called()

        def test_helper_dialog_can_enable_a_saved_tls_profile(self):
            config = self.configured(enabled=False)
            retained = {key: config[key] for key in _HELPER_FIELDS}
            _, mode, _, submit, save, restart, refreshed = self.helper_form(config)
            self.assertEqual(mode.get(), t("helper.mode.direct"))
            mode.set(t("helper.mode.tls-pin"))
            mode.cget("command")(t("helper.mode.tls-pin"))
            with mock.patch.object(helper_settings, "protect_token") as protect:
                submit.invoke()
                protect.assert_not_called()
            save.assert_called_once()
            saved = save.call_args.args[0]
            self.assertIs(saved["helper_enabled"], True)
            self.assertEqual({key: saved[key] for key in _HELPER_FIELDS}, retained)
            restart.assert_called_once_with(config)
            refreshed.assert_called_once_with()
            self.show_error.assert_not_called()

        def test_helper_dialog_can_disable_tls_and_retains_its_transport_and_credentials(self):
            config = self.configured(enabled=True)
            retained = {key: config[key] for key in _HELPER_FIELDS}
            _, mode, _, submit, save, restart, _ = self.helper_form(config)
            self.assertEqual(mode.get(), t("helper.mode.tls-pin"))
            mode.set(t("helper.mode.direct"))
            mode.cget("command")(t("helper.mode.direct"))
            submit.invoke()
            save.assert_called_once()
            saved = save.call_args.args[0]
            self.assertIs(saved["helper_enabled"], False)
            self.assertEqual({key: saved[key] for key in _HELPER_FIELDS}, retained)
            restart.assert_called_once_with(config)
            self.show_error.assert_not_called()

        def test_turning_helper_dialog_off_ignores_invalid_unsaved_fields(self):
            config = self.configured(enabled=True)
            retained = {key: config[key] for key in _HELPER_FIELDS}
            _, mode, fields, submit, save, _, _ = self.helper_form(config)
            fields[t("helper.port_placeholder")].set("not-a-port")
            fields[t("helper.host_placeholder")].set("unsaved.example.invalid")
            fields[t("helper.fingerprint_placeholder")].set("not-a-fingerprint")
            fields[t("helper.token_placeholder")].set("unsaved-new-token")
            mode.set(t("helper.mode.direct"))
            mode.cget("command")(t("helper.mode.direct"))
            with mock.patch.object(helper_settings, "protect_token") as protect:
                submit.invoke()
                protect.assert_not_called()
            save.assert_called_once()
            saved = save.call_args.args[0]
            self.assertIs(saved["helper_enabled"], False)
            self.assertEqual({key: saved[key] for key in _HELPER_FIELDS}, retained)
            self.show_error.assert_not_called()

        def test_switch_is_visible_at_top_of_routes_and_footer_fits_minimum_window(self):
            for language in ("ru", "en"):
                for appearance in ("light", "dark"):
                    with self.subTest(language=language, appearance=appearance):
                        config = self.configured(enabled=False)
                        window, widgets, switch, route, footer = self.form(
                            config, language=language, appearance=appearance,
                        )
                        self.assertEqual(switch.cget("text"), t("settings.use_helper"))
                        self.assertNotEqual(switch.cget("text"), "settings.use_helper")
                        self.assertInside(switch, route._parent_canvas)
                        self.assertInside(switch._text_label, switch)
                        self.assertLess(switch.winfo_rooty(),
                                        route._parent_canvas.winfo_rooty() + 160)
                        self.assertFalse(widgets.helper_fields.winfo_viewable())
                        switch.toggle()
                        self.pump()
                        self.assertTrue(widgets.helper_fields.winfo_viewable())
                        manual = next(button for button in descendants(widgets.helper_fields)
                                      if isinstance(button, self.ctk.CTkButton)
                                      and button.cget("text") == t("pairing.manual"))
                        manual.invoke()
                        self.pump()
                        entries = [entry for entry in descendants(widgets.helper_fields)
                                   if isinstance(entry, self.ctk.CTkEntry)]
                        for key in ("helper_host_var", "helper_port_var",
                                    "helper_fingerprint_var", "helper_token_var"):
                            self.assertTrue(any(entry.cget("textvariable") is getattr(widgets, key)
                                                for entry in entries), key)
                        token = next(entry for entry in entries
                                     if entry.cget("textvariable") is widgets.helper_token_var)
                        self.assertTrue(token.cget("show"))
                        canvas = route._parent_canvas
                        token_y = token.winfo_rooty() - route.winfo_rooty()
                        canvas.yview_moveto(max(0, (token_y - 16) / route.winfo_height()))
                        self.pump()
                        self.assertInside(token, canvas)
                        for button in descendants(footer):
                            if isinstance(button, self.ctk.CTkButton):
                                self.assertInside(button, window)
                        switch.toggle()
                        self.pump()
                        self.assertFalse(widgets.helper_fields.winfo_viewable())
                        self.assertFalse(widgets.helper_enabled_var.get())
                        window.destroy()


if __name__ == "__main__":
    if _NATIVE_MODE:
        sys.argv.remove("--native-run")
    unittest.main()
