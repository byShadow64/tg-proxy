from __future__ import annotations

from typing import Any, Callable, Tuple
from tkinter import Misc, TclError

from proxy import get_link_host
from ui.ctk_controls import create_entry, create_label
from ui.ctk_theme import FIRST_RUN_FRAME_PAD, CtkTheme, main_content_frame
from ui.ctk_tooltip import attach_ctk_tooltip
from ui.icons import icon_image
from ui.i18n import t
from ui.settings_form import (
    TrayConfigFormWidgets as TrayConfigFormWidgets,
    install_tray_config_form as install_tray_config_form,
    validate_config_form as validate_config_form,
)


def tray_settings_scroll_and_footer(
    ctk: Any,
    content_parent: Any,
    theme: CtkTheme,
) -> Tuple[Any, Any]:
    footer = ctk.CTkFrame(content_parent, fg_color="transparent")
    footer.pack(side="bottom", fill="x")
    content = ctk.CTkFrame(content_parent, fg_color="transparent")
    content.pack(fill="both", expand=True)
    return content, footer


def install_tray_config_buttons(
    ctk: Any,
    frame: Any,
    theme: CtkTheme,
    *,
    on_save: Callable[[], None],
    on_cancel: Callable[[], None],
    busy_var: Any = None,
) -> None:
    ctk.CTkFrame(
        frame,
        fg_color=theme.field_border,
        height=1,
        corner_radius=0,
    ).pack(fill="x", pady=(18, 14))
    btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
    btn_frame.pack(fill="x")
    create_label(
        ctk, btn_frame, theme, t("settings.save_hint"), size=11,
        wraplength=245, justify="left",
    ).pack(side="left", fill="x", expand=True, padx=(0, 16))
    save_btn = ctk.CTkButton(
        btn_frame, text=t("button.save"), width=130, height=42,
        image=icon_image("check", theme, 16, color="accent_text"), compound="left",
        font=(theme.ui_font_family, 13, "bold"), corner_radius=10,
        fg_color=theme.accent, hover_color=theme.accent_hover,
        text_color=theme.accent_text,
        command=on_save)
    save_btn.pack(side="right", padx=(8, 0))
    attach_ctk_tooltip(save_btn, t("tip.save"))
    cancel_btn = ctk.CTkButton(
        btn_frame, text=t("button.cancel"), width=100, height=42,
        font=(theme.ui_font_family, 13), corner_radius=10,
        fg_color=theme.field_bg, hover_color=theme.field_border,
        text_color=theme.text_primary, border_width=1,
        border_color=theme.field_border,
        command=on_cancel)
    cancel_btn.pack(side="right")
    attach_ctk_tooltip(cancel_btn, t("tip.cancel"))
    if busy_var is not None:
        def sync_busy(*_):
            state = "disabled" if busy_var.get() else "normal"
            save_btn.configure(state=state)
            cancel_btn.configure(state=state)

        busy_trace = busy_var.trace_add("write", sync_busy)
        sync_busy()

        def release_busy_trace(event):
            if event.widget is frame:
                try:
                    busy_var.trace_remove("write", busy_trace)
                except TclError:
                    pass

        Misc.bind(frame, "<Destroy>", release_busy_trace, add="+")


def populate_first_run_window(
    ctk: Any,
    root: Any,
    theme: CtkTheme,
    *,
    host: str,
    port: int,
    secret: str,
    on_done: Callable[[bool], None],
) -> None:
    link_host = get_link_host(host)
    fpx, fpy = FIRST_RUN_FRAME_PAD
    frame = main_content_frame(ctk, root, theme, padx=fpx, pady=fpy)
    footer = ctk.CTkFrame(frame, fg_color="transparent")
    footer.pack(side="bottom", fill="x", pady=(20, 0))
    content = ctk.CTkScrollableFrame(
        frame, fg_color="transparent", corner_radius=0,
        scrollbar_button_color=theme.field_border,
        scrollbar_button_hover_color=theme.text_secondary,
    )
    content.pack(fill="both", expand=True)

    brand = ctk.CTkFrame(content, fg_color="transparent")
    brand.pack(fill="x", pady=(0, 24))
    ctk.CTkLabel(
        brand, text="", image=icon_image("logo", theme, 44, color="accent"), width=48,
    ).pack(side="left", padx=(0, 12))
    create_label(ctk, brand, theme, "TG Proxy", size=20, bold=True,
                 secondary=False).pack(side="left")
    create_label(ctk, content, theme, t("first_run.heading"), size=28,
                 bold=True, secondary=False).pack(anchor="w")
    subtitle = create_label(
        ctk, content, theme, t("first_run.subtitle"), size=13,
        wraplength=450, justify="left",
    )
    subtitle.pack(fill="x", pady=(4, 22))
    connection = ctk.CTkFrame(
        content, fg_color=theme.field_bg, corner_radius=16,
        border_width=1, border_color=theme.field_border,
    )
    connection.pack(fill="x", pady=(0, 14))
    ctk.CTkLabel(
        connection, text="", image=icon_image("network", theme, 24, color="accent"),
        width=32,
    ).pack(side="left", padx=(18, 12), pady=20)
    address = ctk.CTkFrame(connection, fg_color="transparent")
    address.pack(side="left", fill="x", expand=True, pady=16)
    create_label(ctk, address, theme, t("first_run.local_proxy"), size=11).pack(anchor="w")
    ctk.CTkLabel(
        address, text=f"{link_host}:{port}", anchor="w",
        font=(theme.mono_font_family, 18, "bold"), text_color=theme.text_primary,
    ).pack(fill="x")
    tray_hint = create_label(
        ctk, content, theme, t("first_run.tray_hint"), size=12,
        wraplength=450, justify="left",
    )
    tray_hint.pack(fill="x", pady=(0, 14))
    manual = ctk.CTkFrame(content, fg_color="transparent")
    manual_hint = create_label(
        ctk, manual, theme, t("first_run.manual_hint"), size=12,
        wraplength=450, justify="left",
    )
    manual_hint.pack(fill="x", pady=(0, 12))
    for key, value in (("label.host", link_host), ("label.port", port),
                       ("label.secret", "dd" + secret)):
        create_label(ctk, manual, theme, t(key), size=11).pack(anchor="w", pady=(6, 3))
        variable = ctk.StringVar(master=root, value=str(value))
        create_entry(ctk, manual, theme, var=variable, state="readonly").pack(fill="x")

    expanded = False

    def toggle_manual():
        nonlocal expanded
        expanded = not expanded
        if expanded:
            manual.pack(fill="x", pady=(8, 0))
        else:
            manual.pack_forget()

    manual_button = ctk.CTkButton(
        content, text=t("first_run.manual_toggle"), height=34, anchor="w",
        image=icon_image("key", theme, 16), compound="left",
        fg_color="transparent", hover_color=theme.field_bg,
        text_color=theme.text_secondary,
        font=(theme.ui_font_family, 12), command=toggle_manual,
    )
    manual_button.pack(fill="x")

    def fit_text(event):
        width = max(100, int(event.width / content._get_widget_scaling()) - 12)
        for label in (subtitle, tray_hint, manual_hint):
            label.configure(wraplength=width)

    content.bind("<Configure>", fit_text, add="+")
    ctk.CTkButton(
        footer, text=t("first_run.connect"), height=46, corner_radius=12,
        image=icon_image("arrow-right", theme, 18, color="accent_text"), compound="right",
        font=(theme.ui_font_family, 14, "bold"), fg_color=theme.accent,
        hover_color=theme.accent_hover, text_color=theme.accent_text,
        command=lambda: on_done(True),
    ).pack(fill="x")
    ctk.CTkButton(
        footer, text=t("first_run.later"), height=34,
        font=(theme.ui_font_family, 12), fg_color="transparent",
        hover_color=theme.field_bg, text_color=theme.text_secondary,
        command=lambda: on_done(False),
    ).pack(fill="x", pady=(6, 0))
    root.protocol("WM_DELETE_WINDOW", lambda: on_done(False))
