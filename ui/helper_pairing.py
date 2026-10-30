"""Inline owner-code onboarding; all sockets run outside the Tk thread."""
from __future__ import annotations

import ipaddress

from tkinter import Misc, TclError

from ui.background_task import BackgroundTask
from ui.ctk_controls import create_entry, create_label
from ui.i18n import t
from utils.helper_pairing import PairingCancelled, pair_helper, parse_code, parse_endpoint
from utils.helper_registry import RegistryCancelled, RegistryError, discover_helper


class HelperPairing:
    def __init__(self, ctk, parent, theme, *, on_paired, on_busy=None, host_var=None, automatic=False):
        self.theme, self.on_paired, self.on_busy = theme, on_paired, on_busy
        self.automatic = automatic
        self._busy = self._closed = self._blocked = False
        self.frame = ctk.CTkFrame(parent, fg_color=theme.surface_alt, corner_radius=12)
        inner = ctk.CTkFrame(self.frame, fg_color="transparent")
        inner.pack(fill="x", padx=14, pady=14)
        create_label(ctk, inner, theme, t("pairing.title"), size=13, bold=True).pack(anchor="w")
        create_label(ctk, inner, theme, t("registry.hint" if automatic else "pairing.hint"), size=11,
                     wraplength=360, justify="left").pack(fill="x", pady=(6, 12))
        self.host_var = host_var if host_var is not None else ctk.StringVar(master=parent, value="")
        self.code_var = ctk.StringVar(master=parent, value="")
        self._entries = []
        rows = [("registry.host" if automatic else "pairing.host", self.host_var, False)]
        if not automatic:
            rows.append(("pairing.code", self.code_var, True))
        for key, variable, masked in rows:
            create_label(ctk, inner, theme, t(key), size=11).pack(anchor="w", pady=(0, 4))
            entry = create_entry(ctk, inner, theme, var=variable, height=36, show="•" if masked else "")
            entry.pack(fill="x", pady=(0, 12))
            self._entries.append(entry)
        self.code_entry = self._entries[1] if not automatic else None
        self.connect_button = ctk.CTkButton(
            inner, text=t("pairing.connect"), height=40, corner_radius=10,
            font=(theme.ui_font_family, 12, "bold"), fg_color=theme.accent,
            hover_color=theme.accent_hover, text_color=theme.on_accent, command=self.connect)
        self.connect_button.pack(fill="x")
        self.cancel_button = ctk.CTkButton(
            inner, text=t("button.cancel"), height=32, fg_color="transparent",
            hover_color=theme.field_border, text_color=theme.text_secondary, command=self.cancel)
        self.status = create_label(ctk, inner, theme, "", size=11, height=1,
                                   wraplength=360, justify="left")
        self.status.pack(fill="x", pady=(8, 0))
        self.task = BackgroundTask(self.frame)
        Misc.bind(self.frame, "<Destroy>", self._destroy, add="+")

    @property
    def busy(self):
        return self._busy

    def set_blocked(self, value):
        if self._closed:
            return
        self._blocked = value
        for widget in (self.connect_button, *self._entries):
            widget.configure(state="disabled" if value or self.busy else "normal")

    def _set_busy(self, value):
        self._busy = value
        self.set_blocked(self._blocked)
        if value:
            self.cancel_button.pack(fill="x", pady=(6, 0), before=self.status)
            self.cancel_button.configure(state="normal")
        else:
            self.cancel_button.pack_forget()
        if self.on_busy:
            self.on_busy(value)

    def connect(self):
        if self._closed or self.busy or self._blocked:
            return
        try:
            if self.automatic:
                raw = self.host_var.get().strip()
                if "%" in raw:
                    raise ValueError()
                host, port = str(ipaddress.ip_address(raw)), 8444
            else:
                host, port = parse_endpoint(self.host_var.get())
            code = self.code_var.get().strip()
            if not self.automatic:
                parse_code(code)
        except (TypeError, ValueError):
            self.status.configure(text=t("registry.invalid" if self.automatic else "pairing.invalid"), text_color=self.theme.danger)
            return
        self._set_busy(True)
        self.status.configure(text=t("registry.connecting" if self.automatic else "pairing.connecting"), text_color=self.theme.text_secondary)
        self._clear_code()
        delivered = False

        def work(cancel):
            try:
                return "ok", (discover_helper(host, cancel_event=cancel, force=True) if self.automatic
                              else pair_helper(host, code, port, cancel_event=cancel))
            except (PairingCancelled, RegistryCancelled):
                return "cancelled", None
            except RegistryError as error:
                return ("not_registered" if str(error) == "helper_not_found" else "error"), None
            except Exception:
                return "error", None

        def complete(result):
            nonlocal delivered
            if self._closed:
                return
            state, value = result
            if state == "ok":
                self.on_paired(value)
            delivered = True
            key = "registry.not_registered" if state == "not_registered" else ("registry." if self.automatic else "pairing.") + {"ok": "connected", "cancelled": "cancelled", "error": "error"}[state]
            self.status.configure(text=t(key),
                                  text_color=self.theme.text_secondary if state != "error" else self.theme.danger)

        def finish():
            if self._closed:
                return
            self._clear_code()
            if not delivered:
                prefix = "registry." if self.automatic else "pairing."
                self.status.configure(text=t(prefix + ("cancelled" if self.task.cancel_event.is_set() else "error")))
            self._set_busy(False)

        self.task.start(work, complete, finish, cancellable=True)

    def cancel(self):
        if self._closed or not self.busy:
            return
        self.task.cancel()
        self.cancel_button.configure(state="disabled")

    def _clear_code(self):
        try:
            self.code_var.set("")
        except TclError:
            pass

    def _destroy(self, event):
        if event.widget is not self.frame:
            return
        self._closed = True
        self.task.cancel()
        self.task.closed = True
        if self.task.pending is not None:
            try:
                self.frame.after_cancel(self.task.pending)
            except TclError:
                pass
            self.task.pending = None
        trace = getattr(self.code_entry, "_textvariable_callback_name", "")
        if trace:
            try:
                self.code_var.trace_remove("write", trace)
            except TclError:
                pass
            self.code_entry._textvariable_callback_name = ""
        self._clear_code()
        self._busy = False
        if self.on_busy:
            try:
                self.on_busy(False)
            except TclError:
                pass
