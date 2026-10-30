from __future__ import annotations

import re
import tkinter.messagebox as messagebox
from tkinter import StringVar
from typing import Callable, Optional

from ui.ctk_theme import CtkTheme
from ui.ctk_controls import create_config_section, create_entry, create_label
from ui.icons import icon_image
from ui.i18n import t
from utils.secure_storage import protect_token
from utils.helper_config import effective_helper_mode


def build_helper_settings(ctk, root, theme: CtkTheme, config: dict, *,
                          save_config, restart, on_saved,
                          on_close: Optional[Callable[[], None]] = None) -> None:
    root.title(t("helper.title"))
    root.geometry("560x560")
    root.minsize(460, 420)
    root.configure(fg_color=theme.bg)

    container = ctk.CTkFrame(root, fg_color=theme.bg, corner_radius=0)
    container.pack(fill="both", expand=True, padx=24, pady=20)
    container.grid_columnconfigure(0, weight=1)
    container.grid_rowconfigure(0, weight=1)
    frame = ctk.CTkScrollableFrame(
        container, fg_color="transparent", corner_radius=0,
        scrollbar_button_color=theme.field_border,
        scrollbar_button_hover_color=theme.text_secondary,
    )
    frame.grid(row=0, column=0, sticky="nsew")
    header = ctk.CTkFrame(frame, fg_color="transparent")
    header.pack(fill="x", pady=(0, 14))
    ctk.CTkLabel(
        header, text="", image=icon_image("shield", theme, 30, color="accent"), width=36,
    ).pack(side="left", padx=(0, 12))
    heading = ctk.CTkFrame(header, fg_color="transparent")
    heading.pack(side="left", fill="x", expand=True)
    create_label(ctk, heading, theme, "TG Proxy", size=11).pack(anchor="w")
    create_label(ctk, heading, theme, t("helper.heading"), size=22, bold=True,
                 secondary=False).pack(anchor="w")
    create_label(ctk, frame, theme, t("helper.subtitle"), size=12).pack(fill="x", pady=(0, 16))
    hint = ctk.CTkLabel(
        frame,
        text=t("helper.tls_hint"),
        fg_color=theme.accent_soft, corner_radius=12, padx=14, pady=12,
        wraplength=440, justify="left", anchor="w",
        font=(theme.ui_font_family, 12), text_color=theme.text_secondary,
    )
    hint.pack(fill="x", pady=(0, 14))

    mode_labels = {key: t(f"helper.mode.{key}") for key in ("direct", "tls-pin", "legacy")}
    current_mode = effective_helper_mode(config)
    mode = StringVar(value=mode_labels.get(current_mode, mode_labels["direct"]))
    host = StringVar(value=config.get("helper_host", ""))
    port = StringVar(value=str(config.get("helper_port", 8444)))
    fingerprint = StringVar(value=config.get("helper_fingerprint", ""))
    token_var = StringVar()

    def add_row(label: str, variable, *, placeholder: str = "", show: Optional[str] = None):
        create_label(ctk, fields, theme, label, size=12).pack(anchor="w", pady=(9, 4))
        options = {"show": show} if show else {}
        field = create_entry(ctk, fields, theme, var=variable,
                             placeholder_text=placeholder, **options)
        field.pack(fill="x")
        return field

    mode_section = create_config_section(ctk, frame, theme, t("helper.mode"))

    def selected_mode():
        return next((key for key, label in mode_labels.items() if label == mode.get()), "direct")

    def change_mode(value: str) -> None:
        mode.set(value)
        selected = selected_mode()
        if selected == "legacy" and port.get() == "8444":
            port.set("8443")
        elif selected == "tls-pin" and port.get() == "8443":
            port.set("8444")
        for field in (host_entry, port_entry):
            field.configure(state="disabled" if selected == "direct" else "normal")
        for field in (fingerprint_entry, token_entry):
            field.configure(state="normal" if selected == "tls-pin" else "disabled")
        if selected == "legacy":
            notice.pack(fill="x", pady=(10, 0))
        else:
            notice.pack_forget()

    ctk.CTkOptionMenu(mode_section, variable=mode,
                      values=list(mode_labels.values()), height=42,
                      fg_color=theme.field_bg, button_color=theme.field_border,
                      button_hover_color=theme.accent_soft, text_color=theme.text_primary,
                      dropdown_fg_color=theme.field_bg, dropdown_text_color=theme.text_primary,
                      dropdown_hover_color=theme.accent_soft,
                      font=(theme.ui_font_family, 13), corner_radius=10,
                      command=change_mode).pack(fill="x")
    fields = create_config_section(ctk, frame, theme, t("helper.server_section"))
    host_entry = add_row(t("helper.host"), host, placeholder=t("helper.host_placeholder"))
    port_entry = add_row(t("label.port"), port, placeholder=t("helper.port_placeholder"))
    fingerprint_entry = add_row(t("helper.fingerprint"), fingerprint,
            placeholder=t("helper.fingerprint_placeholder"))
    token_entry = add_row(t("helper.token"), token_var,
            placeholder=t("helper.token_placeholder"), show="•")

    notice = ctk.CTkLabel(
        frame,
        text=t("helper.legacy_notice"),
        fg_color=theme.warning_bg, corner_radius=10, padx=12, pady=10,
        wraplength=440, justify="left", anchor="w",
        font=(theme.ui_font_family, 11), text_color=theme.text_secondary,
    )
    change_mode(mode.get())

    def fit_text(event):
        width = max(100, int(event.width / frame._get_widget_scaling()) - 12)
        for label in (hint, notice):
            if label.cget("wraplength") != width:
                label.configure(wraplength=width)

    frame.bind("<Configure>", fit_text, add="+")
    footer = ctk.CTkFrame(container, fg_color="transparent")
    footer.grid(row=1, column=0, sticky="ew", pady=(16, 0))

    def close() -> None:
        root.destroy()
        if on_close:
            on_close()

    def submit() -> None:
        selected = selected_mode()
        new_cfg = dict(config)
        new_cfg["helper_enabled"] = selected != "direct"
        # Turning the helper off retains its transport for the settings switch.
        new_cfg["helper_mode"] = (
            selected if selected != "direct" else config.get("helper_mode", "direct")
        )
        if selected != "direct":
            new_cfg["helper_host"] = host.get().strip()
            try:
                port_num = int(port.get().strip())
            except ValueError:
                messagebox.showerror(t("helper.title"), t("validation.bad_port"), parent=root)
                return
            if not 1 <= port_num <= 65535:
                messagebox.showerror(t("helper.title"), t("validation.bad_port"), parent=root)
                return
            new_cfg["helper_port"] = port_num
            new_cfg["helper_fingerprint"] = fingerprint.get().strip()
            if not new_cfg["helper_host"]:
                messagebox.showerror(t("helper.title"), t("helper.host_required"), parent=root)
                return
        if selected == "tls-pin":
            normalized = new_cfg["helper_fingerprint"].lower().replace(":", "").replace(" ", "")
            if not re.fullmatch(r"[0-9a-f]{64}", normalized):
                messagebox.showerror(t("helper.title"), t("helper.bad_fingerprint"), parent=root)
                return
            new_cfg["helper_fingerprint"] = normalized
            if token_var.get().strip():
                try:
                    new_cfg["helper_token_dpapi"] = protect_token(token_var.get().strip())
                except Exception as exc:
                    messagebox.showerror(t("helper.title"), t("helper.protect_failed", error=exc), parent=root)
                    return
            elif not new_cfg.get("helper_token_dpapi"):
                messagebox.showerror(t("helper.title"), t("helper.token_required"), parent=root)
                return
        try:
            save_config(new_cfg)
            config.clear()
            config.update(new_cfg)
            restart(config)
            on_saved()
            close()
        except Exception as exc:
            messagebox.showerror(t("helper.title"), t("helper.save_failed", error=exc), parent=root)

    ctk.CTkButton(footer, text=t("helper.save_restart"), height=42, corner_radius=10,
                  fg_color=theme.accent, hover_color=theme.accent_hover,
                  text_color=theme.accent_text, font=(theme.ui_font_family, 12, "bold"),
                  command=submit).pack(side="left", fill="x", expand=True, padx=(0, 8))
    ctk.CTkButton(footer, text=t("button.cancel"), height=42, corner_radius=10, fg_color=theme.field_bg,
                  hover_color=theme.field_border, text_color=theme.text_primary,
                  font=(theme.ui_font_family, 12),
                  border_width=1, border_color=theme.field_border,
                  command=close).pack(side="right", fill="x", expand=True)
    root.protocol("WM_DELETE_WINDOW", close)
