"""Inline helper connection editor; secrets leave it only after encryption."""
from __future__ import annotations

import re
from tkinter import Misc, TclError

from ui.ctk_controls import create_config_section, create_entry, create_label
from ui.i18n import t
from ui.helper_pairing import HelperPairing
from ui.ssh_setup import SSHSetup
from utils.helper_config import helper_is_enabled
from utils.secure_storage import protect_token


class HelperForm:
    def __init__(self, ctk, parent, theme, config):
        self.section = create_config_section(ctk, parent, theme, "Helper-server")
        self.enabled = ctk.BooleanVar(master=parent, value=helper_is_enabled(config))
        saved_mode = config.get("helper_mode", "tls-pin")
        self.mode = ctk.StringVar(master=parent, value=(
            saved_mode if saved_mode in ("tls-pin", "legacy") else "tls-pin"))
        self._last_mode = self.mode.get()
        self.host = ctk.StringVar(master=parent, value=config.get("helper_host", ""))
        self.port = ctk.StringVar(master=parent, value=str(config.get("helper_port", 8444)))
        self.fingerprint = ctk.StringVar(master=parent, value=config.get("helper_fingerprint", ""))
        self.token = ctk.StringVar(master=parent, value="")
        self.registry = ctk.BooleanVar(master=parent, value=config.get("helper_registry") is True)
        self.busy_var = ctk.BooleanVar(master=parent, value=False)
        self.toggle = ctk.CTkSwitch(
            self.section, text=t("settings.use_helper"), variable=self.enabled,
            font=(theme.ui_font_family, 13), text_color=theme.text_primary,
            fg_color=theme.field_border, progress_color=theme.accent,
            button_color=theme.text_secondary, button_hover_color=theme.text_primary,
            switch_width=42, switch_height=24, height=30,
        )
        self.toggle.pack(anchor="w")
        create_label(
            ctk, self.section, theme, t("settings.helper_toggle_hint"),
            size=11, wraplength=360, justify="left",
        ).pack(fill="x", pady=(7, 0))
        self.fields = ctk.CTkFrame(self.section, fg_color="transparent")
        self.advanced = ctk.CTkFrame(self.fields, fg_color="transparent")
        self._advanced_expanded = False
        mode_label = create_label(ctk, self.advanced, theme, t("helper.mode"), size=11)
        mode_label.pack(anchor="w", pady=(0, 4))
        self.mode_menu = ctk.CTkOptionMenu(
            self.advanced, values=[t(f"helper.mode.{mode}") for mode in ("tls-pin", "legacy")],
            height=36, corner_radius=9, font=(theme.ui_font_family, 12),
            fg_color=theme.field_bg, button_color=theme.field_border,
            button_hover_color=theme.accent_soft, text_color=theme.text_primary,
            dropdown_fg_color=theme.surface, dropdown_text_color=theme.text_primary,
            dropdown_hover_color=theme.accent_soft,
            command=lambda value: self.mode.set(next(
                mode for mode in ("tls-pin", "legacy") if t(f"helper.mode.{mode}") == value)),
        )
        self.mode_menu.pack(fill="x", pady=(0, 12))
        address = ctk.CTkFrame(self.advanced, fg_color="transparent")
        address.pack(fill="x", pady=(0, 12))
        address.grid_columnconfigure(0, weight=3)
        address.grid_columnconfigure(1, weight=1)
        self.address_entries = []
        for column, label, variable in ((0, "helper.host", self.host), (1, "label.port", self.port)):
            cell = ctk.CTkFrame(address, fg_color="transparent")
            cell.grid(row=0, column=column, sticky="ew", padx=(0, 10) if column == 0 else 0)
            create_label(ctk, cell, theme, t(label), size=11).pack(anchor="w", pady=(0, 4))
            entry = create_entry(ctk, cell, theme, var=variable, width=1, height=36)
            entry.pack(fill="x")
            self.address_entries.append(entry)
        self.tls_entries = []
        for label, variable, masked in (("helper.fingerprint", self.fingerprint, False),
                                        ("helper.token", self.token, True)):
            create_label(ctk, self.advanced, theme, t(label), size=11).pack(anchor="w", pady=(0, 4))
            entry = create_entry(ctk, self.advanced, theme, var=variable, height=36,
                                 show="•" if masked else "")
            entry.pack(fill="x", pady=(0, 12))
            self.tls_entries.append(entry)
        self.token_hint = create_label(
            ctk, self.advanced, theme, "", size=11, wraplength=360, justify="left")
        self.token_hint.pack(fill="x")
        self._has_saved_token = bool(config.get("helper_token_dpapi"))
        self.pairing = HelperPairing(
            ctk, self.fields, theme, on_paired=self._registered,
            on_busy=self._pairing_busy, host_var=self.host, automatic=True,
        )
        self.pairing.frame.pack(fill="x", pady=(0, 16))
        self.ssh_setup = SSHSetup(
            ctk, self.fields, theme, on_installed=self._installed,
            on_busy=self._ssh_busy, host_var=self.host,
            registry_default=config.get("helper_registry") is True or not config.get("helper_host"),
        )
        self.ssh_setup.frame.pack(fill="x", pady=(0, 16), after=self.pairing.frame)
        self.advanced_button = ctk.CTkButton(
            self.fields, text=t("pairing.manual"), height=36, anchor="w",
            fg_color="transparent", hover_color=theme.field_border,
            text_color=theme.accent, font=(theme.ui_font_family, 12),
            command=self._toggle_advanced,
        )
        self.advanced_button.pack(fill="x")
        self._enabled_trace = self.enabled.trace_add("write", self._sync_visibility)
        self._mode_trace = self.mode.trace_add("write", self._sync_mode)
        Misc.bind(self.section, "<Destroy>", self._destroy, add="+")
        self._sync_mode()
        self._sync_visibility()

    def _sync_visibility(self, *_):
        if self.enabled.get():
            self.fields.pack(fill="x", pady=(16, 0))
        else:
            self.fields.pack_forget()

    def _toggle_advanced(self):
        self._advanced_expanded = not self._advanced_expanded
        if self._advanced_expanded:
            self.advanced.pack(fill="x", pady=(8, 0))
        else:
            self.advanced.pack_forget()

    def _ssh_busy(self, busy):
        self.pairing.set_blocked(busy)
        self._connection_busy(busy)

    def _pairing_busy(self, busy):
        setup = getattr(self, "ssh_setup", None)
        if setup is not None and not setup._closed:
            for widget in (setup.header_button, setup.install_button, *setup._entries):
                widget.configure(state="disabled" if busy else "normal")
        self._connection_busy(busy)

    def _connection_busy(self, busy):
        self.busy_var.set(busy)
        self.toggle.configure(state="disabled" if busy else "normal")
        self.mode_menu.configure(state="disabled" if busy else "normal")
        for entry in self.address_entries:
            entry.configure(state="disabled" if busy else "normal")
        self._sync_mode()

    def _installed(self, result):
        if getattr(result, "registry", False):
            return self._registered(result)
        self.registry.set(False)
        self.mode.set("tls-pin")
        self.host.set(result.host)
        self.port.set(str(result.port))
        self.fingerprint.set(result.tls_fingerprint)
        self.token.set(result.token)
        self.enabled.set(True)

    def _registered(self, result):
        self.mode.set("tls-pin")
        self.host.set(result.host)
        self.port.set(str(result.port))
        self.fingerprint.set(result.fingerprint)
        self.token.set("")
        self.registry.set(True)
        self.enabled.set(True)


    def _sync_mode(self, *_):
        selected = self.mode.get()
        if selected not in ("tls-pin", "legacy"):
            selected = "tls-pin"
        if selected != self._last_mode:
            if selected == "tls-pin" and self.port.get() == "8443":
                self.port.set("8444")
            elif selected == "legacy" and self.port.get() == "8444":
                self.port.set("8443")
        self._last_mode = selected
        self.mode_menu.set(t(f"helper.mode.{selected}"))
        for entry in self.tls_entries:
            entry.configure(state="normal" if selected == "tls-pin" and not self.busy_var.get() else "disabled")
        key = ("helper.legacy_notice" if selected == "legacy" else
               "helper.token_saved_hint" if self._has_saved_token else "helper.token_new_hint")
        self.token_hint.configure(text=t(key))

    def _destroy(self, event):
        if event.widget is self.section:
            for variable, trace in ((self.enabled, self._enabled_trace), (self.mode, self._mode_trace)):
                try:
                    variable.trace_remove("write", trace)
                except TclError:
                    pass


def validate_helper_values(current, *, enabled, mode, host, port, fingerprint, token, registry=False):
    if not enabled:
        return {"helper_enabled": False}
    mode = mode if mode in ("tls-pin", "legacy") else "tls-pin"
    host = host.strip()
    if not host:
        return t("helper.host_required")
    try:
        port = int(port.strip())
    except (TypeError, ValueError):
        return t("validation.bad_port")
    if not 1 <= port <= 65535:
        return t("validation.bad_port")
    values = {"helper_enabled": True, "helper_mode": mode, "helper_host": host, "helper_port": port}
    managed = registry is True and mode == "tls-pin" and not token.strip()
    if managed or current.get("helper_registry") is True:
        values["helper_registry"] = managed
    if mode == "tls-pin":
        fingerprint = fingerprint.strip().lower().replace(":", "").replace(" ", "")
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            return t("helper.bad_fingerprint")
        token = token.strip()
        if not token and not current.get("helper_token_dpapi") and not managed:
            return t("helper.token_required")
        values["helper_fingerprint"] = fingerprint
        if token:
            try:
                values["helper_token_dpapi"] = protect_token(token)
            except Exception as exc:
                return t("helper.protect_failed", error=type(exc).__name__)
    return values
