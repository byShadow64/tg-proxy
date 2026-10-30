from __future__ import annotations

import os
import webbrowser
from dataclasses import dataclass
from tkinter import TclError
from typing import Any, Callable, Dict, List, Optional, Union

from proxy import __version__, coerce_domain_list
from proxy.project import REPOSITORY_URL
from proxy.balancer import balancer
from utils.update_check import RELEASES_PAGE_URL, get_status, run_check
from ui.helper_form import HelperForm, validate_helper_values
from ui.background_task import BackgroundTask
from ui.external_links import open_release_page
from ui.connectivity import (
    run_cfproxy_multi_test, run_cfproxy_auto_test, run_cfworker_multi_test,
    show_connectivity_results, show_multi_connectivity_results,
)
from ui.ctk_controls import (
    create_entry, create_checkbox, create_label, create_labeled_entry,
    create_config_section, create_combobox,
)
from ui.ctk_theme import CtkTheme
from ui.icons import icon_image
from ui.ctk_tooltip import attach_ctk_tooltip, attach_tooltip_to_widgets
from ui.settings import validate_settings
from ui.i18n import (
    label_from_language, language_from_label, language_option_labels,
    set_language, get_language, t,
)

_INNER_W = 396
_APPEARANCE_KEYS = ("auto", "light", "dark")
_APPEARANCE_TO_CTK = {"auto": "system", "light": "Light", "dark": "Dark"}


def _get_doc_url(doc_name: str) -> str:
    lang = get_language().value
    lang_folder = "EN" if lang == "en" else "RU"
    return f"{REPOSITORY_URL}/blob/main/docs/{lang_folder}/{doc_name}.md"


def _appearance_options() -> List[str]:
    return [t(f"appearance.{key}") for key in _APPEARANCE_KEYS]


def _appearance_from_cfg(value: str) -> str:
    if value in _APPEARANCE_KEYS:
        return t(f"appearance.{value}")
    return t("appearance.auto")


def _appearance_to_cfg(label: str) -> str:
    for key in _APPEARANCE_KEYS:
        if t(f"appearance.{key}") == label:
            return key
    return "auto"


@dataclass
class TrayConfigFormWidgets:
    host_var: Any
    port_var: Any
    secret_var: Any
    dc_textbox: Any
    verbose_var: Any
    no_secure_var: Any
    advanced_vars: Dict[str, Any]
    autostart_var: Optional[Any]
    check_updates_var: Optional[Any]
    auto_install_updates_var: Optional[Any] = None
    cfproxy_var: Optional[Any] = None
    h2_var: Optional[Any] = None
    cfproxy_user_domain_enabled_var: Optional[Any] = None
    cfproxy_user_domain_var: Optional[Any] = None
    cfproxy_worker_enabled_var: Optional[Any] = None
    cfproxy_worker_domain_var: Optional[Any] = None
    appearance_var: Optional[Any] = None
    language_var: Optional[Any] = None
    helper_enabled_var: Optional[Any] = None
    helper_config: Optional[dict] = None
    helper_host_var: Optional[Any] = None
    helper_port_var: Optional[Any] = None
    helper_fingerprint_var: Optional[Any] = None
    helper_token_var: Optional[Any] = None
    helper_registry_var: Optional[Any] = None
    helper_mode_var: Optional[Any] = None
    helper_fields: Optional[Any] = None
    helper_busy_var: Optional[Any] = None
    select_page: Optional[Any] = None


def install_tray_config_form(
    ctk: Any,
    frame: Any,
    theme: CtkTheme,
    cfg: dict,
    default_config: dict,
    *,
    show_autostart: bool = False,
    autostart_value: bool = False,
    on_update_click: Optional[Callable[[], None]] = None,
    initial_page: str = "connection",
) -> TrayConfigFormWidgets:
    set_language(cfg.get("language", default_config["language"]))
    no_secure_var = ctk.BooleanVar(master=frame, value=cfg.get("no_secure", False))

    _create_header(ctk, frame, theme)
    page_host = ctk.CTkFrame(frame, fg_color="transparent")
    pages = {}
    tab_keys = ("connection", "routes", "application", "advanced")

    def select_page(label):
        for key, page in pages.items():
            if label == t(f"settings.tab.{key}"):
                page.grid()
            else:
                page.grid_remove()

    navigation = ctk.CTkSegmentedButton(
        frame, values=[t(f"settings.tab.{key}") for key in tab_keys],
        command=select_page, height=40, corner_radius=10,
        font=(theme.ui_font_family, 12, "bold"),
        fg_color=theme.field_bg, selected_color=theme.accent_soft,
        selected_hover_color=theme.accent_soft,
        unselected_color=theme.field_bg,
        unselected_hover_color=theme.field_border,
        text_color=theme.text_primary, text_color_disabled=theme.text_secondary,
    )
    navigation.pack(fill="x", pady=(18, 16))
    page_host.pack(fill="both", expand=True)
    page_host.grid_columnconfigure(0, weight=1)
    page_host.grid_rowconfigure(0, weight=1)
    for key in tab_keys:
        page = ctk.CTkScrollableFrame(
            page_host, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=theme.field_border,
            scrollbar_button_hover_color=theme.text_secondary,
        )
        page.grid(row=0, column=0, sticky="nsew")
        create_label(
            ctk, page, theme, t(f"settings.{key}_hint"),
            size=12, justify="left", wraplength=470,
        ).pack(fill="x", pady=(0, 16))
        pages[key] = page
    appearance_var, language_var = _create_interface(
        ctk, pages["application"], theme, cfg, default_config,
    )
    host_var, port_var, secret_var = _create_connection(
        ctk, pages["connection"], theme, cfg, default_config,
    )
    helper = HelperForm(ctk, pages["routes"], theme, cfg)
    dc_textbox = _create_dc(ctk, pages["routes"], theme, cfg, default_config)
    cfproxy_var, h2_var, cf_custom_cb_var, cfproxy_user_domain_var = _create_cfproxy(
        ctk, pages["routes"], theme, cfg, default_config, no_secure_var,
    )
    cfproxy_worker_enabled_var, cfproxy_worker_domain_var = _create_cfworker(
        ctk, pages["routes"], theme, cfg, default_config, no_secure_var,
    )
    verbose_var, advanced_vars = _create_logging(
        ctk, pages["advanced"], theme, cfg, default_config, no_secure_var,
    )
    check_updates_var, auto_install_updates_var = _create_updates(
        ctk, pages["application"], theme, cfg, default_config, on_update_click,
    )
    autostart_var = _create_autostart(
        ctk, pages["application"], theme, show_autostart, autostart_value,
    )

    # Select the requested page after all controls have been constructed.
    initial_page = initial_page if initial_page in tab_keys else "connection"
    navigation.set(t(f"settings.tab.{initial_page}"))
    select_page(t(f"settings.tab.{initial_page}"))

    def navigate(key):
        if key in tab_keys:
            label = t(f"settings.tab.{key}")
            navigation.set(label)
            select_page(label)

    return TrayConfigFormWidgets(
        host_var=host_var, port_var=port_var, secret_var=secret_var,
        dc_textbox=dc_textbox, verbose_var=verbose_var, no_secure_var=no_secure_var,
        advanced_vars=advanced_vars,
        autostart_var=autostart_var, check_updates_var=check_updates_var,
        auto_install_updates_var=auto_install_updates_var,
        cfproxy_var=cfproxy_var,
        h2_var=h2_var,
        cfproxy_user_domain_enabled_var=cf_custom_cb_var,
        cfproxy_user_domain_var=cfproxy_user_domain_var,
        cfproxy_worker_enabled_var=cfproxy_worker_enabled_var,
        cfproxy_worker_domain_var=cfproxy_worker_domain_var,
        appearance_var=appearance_var,
        language_var=language_var,
        helper_enabled_var=helper.enabled,
        helper_config=dict(cfg),
        helper_host_var=helper.host, helper_port_var=helper.port,
        helper_fingerprint_var=helper.fingerprint, helper_token_var=helper.token,
        helper_registry_var=helper.registry,
        helper_mode_var=helper.mode, helper_fields=helper.fields,
        helper_busy_var=helper.busy_var,
        select_page=navigate,
    )


def _create_header(ctk, frame, theme):
    header = ctk.CTkFrame(frame, fg_color="transparent")
    header.pack(fill="x")
    ctk.CTkLabel(
        header, text="", image=icon_image("logo", theme, 36, color="accent"), width=42,
    ).pack(side="left", padx=(0, 12))
    copy = ctk.CTkFrame(header, fg_color="transparent")
    copy.pack(side="left", fill="x", expand=True)
    create_label(ctk, copy, theme, "TG Proxy", size=12).pack(anchor="w")
    ctk.CTkLabel(
        copy, text=t("settings.title"),
        font=(theme.ui_font_family, 24, "bold"),
        text_color=theme.text_primary, anchor="w",
    ).pack(anchor="w")
    ctk.CTkLabel(
        header, text=f"v{__version__}",
        font=(theme.mono_font_family, 11),
        text_color=theme.text_secondary, anchor="e",
    ).pack(side="right", padx=(4, 0))
    create_label(
        ctk, frame, theme, t("settings.subtitle"), size=12,
        justify="left", wraplength=480,
    ).pack(fill="x", pady=(12, 0))


def _create_interface(ctk, frame, theme, cfg, default_config):
    lang_cfg = cfg.get("language", default_config["language"])
    appearance_var = ctk.StringVar(
        master=frame, value=_appearance_from_cfg(cfg.get("appearance", "auto"))
    )

    def _on_appearance_change(choice: str) -> None:
        cfg_val = _appearance_to_cfg(choice)
        owner = frame.winfo_toplevel()
        ctk.set_appearance_mode(_APPEARANCE_TO_CTK[cfg_val])

        def restore_dialog():
            try:
                if owner.winfo_exists():
                    # CTk can leave an owned dialog withdrawn after its
                    # Windows titlebar redraw. Raising/focusing alone does
                    # not remap it; restore visibility after the redraw.
                    owner.deiconify()
                    owner.lift()
                    owner.focus_force()
            except TclError:
                pass  # The settings window or its Tk root was closed meanwhile.

        # CTk redraws every Windows titlebar when appearance changes. Restore
        # this dialog after those withdraw/deiconify callbacks have finished.
        # Register on the app root so closing the dialog before the timer fires
        # cannot leave a deleted Tcl callback in the event queue.
        owner._root().after(100, restore_dialog)

    ui_inner = create_config_section(ctk, frame, theme, t("section.interface"))
    ui_row = ctk.CTkFrame(ui_inner, fg_color="transparent")
    ui_row.pack(fill="x")

    lang_col = ctk.CTkFrame(ui_row, fg_color="transparent")
    lang_col.pack(side="left", fill="x", expand=True, padx=(0, 8))

    theme_col = ctk.CTkFrame(ui_row, fg_color="transparent")
    theme_col.pack(side="left", fill="x", expand=True, padx=(8, 0))

    language_var = ctk.StringVar(master=frame, value=label_from_language(lang_cfg))
    create_label(ctk, lang_col, theme, t("settings.language"), size=11).pack(
        anchor="w", pady=(0, 2)
    )
    create_combobox(
        ctk, lang_col, theme, variable=language_var,
        values=[label for _, label in language_option_labels()],
    ).pack(fill="x")
    create_label(ctk, theme_col, theme, t("settings.theme"), size=11).pack(
        anchor="w", pady=(0, 2)
    )
    create_combobox(
        ctk, theme_col, theme, variable=appearance_var,
        values=_appearance_options(), command=_on_appearance_change,
    ).pack(fill="x")
    return appearance_var, language_var


def _create_connection(ctk, frame, theme, cfg, default_config):
    conn = create_config_section(ctk, frame, theme, t("section.mtproto"))

    host_row = ctk.CTkFrame(conn, fg_color="transparent")
    host_row.pack(fill="x")

    host_col, host_var = create_labeled_entry(
        ctk, host_row, theme, t("label.host"),
        cfg.get("host", default_config["host"]),
        tip=t("tip.host"), width=160, pack_fill=True,
    )
    host_col.pack(side="left", fill="x", expand=True, padx=(0, 10))

    port_col, port_var = create_labeled_entry(
        ctk, host_row, theme, t("label.port"),
        cfg.get("port", default_config["port"]),
        tip=t("tip.port"), width=100,
    )
    port_col.pack(side="left")

    secret_row = ctk.CTkFrame(conn, fg_color="transparent")
    secret_row.pack(fill="x", pady=(14, 0))
    secret_heading = ctk.CTkFrame(secret_row, fg_color="transparent")
    secret_heading.pack(fill="x", pady=(0, 6))
    secret_label = create_label(ctk, secret_heading, theme, t("label.secret"))
    secret_label.pack(side="left")
    secret_var = ctk.StringVar(master=frame, value=cfg.get("secret", default_config["secret"]))
    secret_visible = False

    def regenerate_secret():
        nonlocal secret_visible
        secret_var.set(os.urandom(16).hex())
        secret_visible = False
        secret_entry.configure(show="•")
        reveal_button.configure(text=t("button.show"))

    ctk.CTkButton(
        secret_heading, text=t("settings.regenerate"), width=118, height=28,
        image=icon_image("refresh", theme, 16), compound="left",
        font=(theme.ui_font_family, 12), corner_radius=10,
        fg_color="transparent", hover_color=theme.field_bg,
        text_color=theme.text_secondary,
        command=regenerate_secret,
    ).pack(side="right")
    secret_input = ctk.CTkFrame(secret_row, fg_color="transparent")
    secret_input.pack(fill="x")
    secret_entry = create_entry(ctk, secret_input, theme, var=secret_var, show="•")
    secret_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

    def toggle_secret():
        nonlocal secret_visible
        secret_visible = not secret_visible
        secret_entry.configure(show="" if secret_visible else "•")
        reveal_button.configure(text=t("button.hide" if secret_visible else "button.show"))

    reveal_button = ctk.CTkButton(
        secret_input, text=t("button.show"), width=84, height=42, corner_radius=10,
        font=(theme.ui_font_family, 12), fg_color=theme.field_bg,
        hover_color=theme.field_border, text_color=theme.text_primary,
        border_width=1, border_color=theme.field_border, command=toggle_secret,
    )
    reveal_button.pack(side="right")
    attach_tooltip_to_widgets([secret_label, secret_entry], t("tip.secret"))
    return host_var, port_var, secret_var


def _create_dc(ctk, frame, theme, cfg, default_config):
    dc_inner = create_config_section(ctk, frame, theme, t("section.dc"))
    dc_lbl = create_label(ctk, dc_inner, theme, t("label.dc_hint"), size=11)
    dc_lbl.pack(anchor="w", pady=(0, 4))
    dc_textbox = ctk.CTkTextbox(
        dc_inner, width=_INNER_W, height=88,
        font=(theme.mono_font_family, 12), corner_radius=10,
        fg_color=theme.bg, border_color=theme.field_border,
        border_width=1, text_color=theme.text_primary,
    )
    dc_textbox.pack(fill="x")
    dc_textbox.insert("1.0", "\n".join(cfg.get("dc_ip", default_config["dc_ip"])))
    attach_tooltip_to_widgets([dc_lbl, dc_textbox], t("tip.dc"))
    return dc_textbox


def _create_cfproxy(ctk, frame, theme, cfg, default_config, no_secure_var):
    cf_inner = create_config_section(ctk, frame, theme, t("section.cfproxy"))

    cf_row = ctk.CTkFrame(cf_inner, fg_color="transparent")
    cf_row.pack(fill="x", pady=(0, 4))

    cfproxy_var = ctk.BooleanVar(
        master=frame, value=cfg.get("cfproxy", default_config.get("cfproxy", True))
    )
    cf_cb = create_checkbox(ctk, cf_row, theme, t("label.cf_enable"), cfproxy_var)
    cf_cb.pack(side="left", padx=(0, 16))
    attach_ctk_tooltip(cf_cb, t("tip.cfproxy"))

    cf_test = BackgroundTask(frame.winfo_toplevel())

    def _on_cf_test():
        secure = not no_secure_var.get()
        user_domains = (
            coerce_domain_list(cfproxy_user_domain_var.get())
            if cf_custom_cb_var.get() else []
        )
        if cf_test.running:
            cf_test.cancel()
            _cf_test_widget.configure(text=t("button.cancelling"), state="disabled")
            return
        _cf_test_widget.configure(text=t("button.cancel"), state="normal")

        def finish():
            _cf_test_widget.configure(text=t("button.test"), state="normal")

        if user_domains:
            cf_test.start(
                lambda cancel: run_cfproxy_multi_test(user_domains, secure=secure, cancel=cancel),
                lambda per: show_multi_connectivity_results(
                    t("connectivity.cfproxy_title"), per, label_prefix="kws",
                    parent=frame.winfo_toplevel(),
                ),
                finish,
                cancellable=True,
            )
        else:
            domains = list(balancer.domains)
            cf_test.start(
                lambda cancel: run_cfproxy_auto_test(domains, secure=secure, cancel=cancel),
                lambda result: show_connectivity_results(
                    t("connectivity.cfproxy_title"), result[1],
                    domain=result[0] or "", auto_mode=True,
                    unavailable_message=t("connectivity.cf_auto_fail"),
                    parent=frame.winfo_toplevel(),
                ),
                finish,
                cancellable=True,
            )

    _cf_test_widget = ctk.CTkButton(
        cf_row, text=t("button.test"), width=74, height=34,
        font=(theme.ui_font_family, 13), corner_radius=8,
        fg_color=theme.field_bg, hover_color=theme.field_border,
        text_color=theme.text_primary, border_width=1, border_color=theme.field_border,
        command=_on_cf_test,
    )
    _cf_test_widget.pack(side="right")

    h2_var = ctk.BooleanVar(master=frame, value=cfg.get("h2", default_config.get("h2", True)))
    h2_cb = create_checkbox(ctk, cf_inner, theme, t("label.h2_enable"), h2_var)
    h2_cb.pack(anchor="w", pady=(2, 8))
    attach_ctk_tooltip(h2_cb, t("tip.h2"))

    def _sync_h2(*_):
        enabled = cfproxy_var.get() and not no_secure_var.get() and not cfg.get("force_test_dc", False)
        h2_cb.configure(state="normal" if enabled else "disabled")

    cfproxy_var.trace_add("write", _sync_h2)
    no_secure_var.trace_add("write", _sync_h2)
    _sync_h2()

    cf_custom_row = ctk.CTkFrame(cf_inner, fg_color="transparent")
    cf_custom_row.pack(fill="x")

    saved_user_domains = coerce_domain_list(
        cfg.get("cfproxy_user_domain", default_config.get("cfproxy_user_domain", ""))
    )
    cf_custom_cb_var = ctk.BooleanVar(
        master=frame, value=cfg.get("cfproxy_user_domain_enabled", bool(saved_user_domains))
    )
    cf_custom_cb = create_checkbox(ctk, cf_custom_row, theme, t("label.cf_custom_domain"), cf_custom_cb_var)
    cf_custom_cb.pack(side="left", padx=(0, 10))
    attach_ctk_tooltip(cf_custom_cb, t("tip.cfproxy_user_domain_cb"))

    ctk.CTkButton(
        cf_custom_row, text="?", width=28, height=32,
        font=(theme.ui_font_family, 14), corner_radius=8,
        fg_color=theme.field_bg, hover_color=theme.field_border,
        text_color=theme.text_primary, border_width=1, border_color=theme.field_border,
        command=lambda: webbrowser.open(_get_doc_url("CfProxy")),
    ).pack(side="right")

    cfproxy_user_domain_var = ctk.StringVar(master=frame, value=", ".join(saved_user_domains))
    cf_domain_entry = create_entry(
        ctk, cf_custom_row, theme, var=cfproxy_user_domain_var,
        height=32, radius=8,
    )
    cf_domain_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
    attach_ctk_tooltip(cf_domain_entry, t("tip.cfproxy_domain"))

    def _sync_domain_entry(*_):
        state = "normal" if cf_custom_cb_var.get() else "disabled"
        cf_domain_entry.configure(state=state)

    cf_custom_cb_var.trace_add("write", _sync_domain_entry)
    _sync_domain_entry()
    return cfproxy_var, h2_var, cf_custom_cb_var, cfproxy_user_domain_var


def _create_cfworker(ctk, frame, theme, cfg, default_config, no_secure_var):
    cf_worker_inner = create_config_section(ctk, frame, theme, t("section.cfworker"))

    cf_worker_row = ctk.CTkFrame(cf_worker_inner, fg_color="transparent")
    cf_worker_row.pack(fill="x", pady=(0, 4))
    cf_worker_lbl = create_label(ctk, cf_worker_row, theme, t("label.cfworker_domains"), size=11)
    cf_worker_lbl.pack(side="left", anchor="w", pady=(0, 2))

    cf_worker_input = ctk.CTkFrame(cf_worker_inner, fg_color="transparent")
    cf_worker_input.pack(fill="x")

    saved_worker_domains = coerce_domain_list(
        cfg.get("cfproxy_worker_domain", default_config.get("cfproxy_worker_domain", ""))
    )
    cfproxy_worker_enabled_var = ctk.BooleanVar(
        master=frame, value=cfg.get("cfproxy_worker_enabled", bool(saved_worker_domains))
    )
    cf_worker_cb = create_checkbox(
        ctk, cf_worker_input, theme, t("label.cf_custom_domain"),
        cfproxy_worker_enabled_var,
    )
    cf_worker_cb.pack(side="left", padx=(0, 10))
    attach_ctk_tooltip(cf_worker_cb, t("tip.cfworker_domain"))

    cfproxy_worker_domain_var = ctk.StringVar(master=frame, value=", ".join(saved_worker_domains))
    cf_worker_entry = create_entry(
        ctk, cf_worker_input, theme, var=cfproxy_worker_domain_var,
        height=32, radius=8,
    )
    cf_worker_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
    attach_tooltip_to_widgets([cf_worker_lbl, cf_worker_entry], t("tip.cfworker_domain"))

    worker_test = BackgroundTask(frame.winfo_toplevel())

    def _sync_cfworker_test_button(*_):
        btn = _cfworker_test_widget
        enabled = (
            not worker_test.cancel_event.is_set() if worker_test.running else
            cfproxy_worker_enabled_var.get() and bool(coerce_domain_list(cfproxy_worker_domain_var.get()))
        )
        btn.configure(state="normal" if enabled else "disabled")

    def _on_cfworker_test():
        secure = not no_secure_var.get()
        domains = coerce_domain_list(cfproxy_worker_domain_var.get())
        if worker_test.running:
            worker_test.cancel()
            _cfworker_test_widget.configure(text=t("button.cancelling"), state="disabled")
            return
        if not cfproxy_worker_enabled_var.get() or not domains:
            return
        _cfworker_test_widget.configure(text=t("button.cancel"), state="normal")

        def finish():
            _cfworker_test_widget.configure(text=t("button.test"))
            _sync_cfworker_test_button()

        worker_test.start(
            lambda cancel: run_cfworker_multi_test(domains, secure=secure, cancel=cancel),
            lambda per: show_multi_connectivity_results(
                t("connectivity.cfworker_title"), per, label_prefix="DC",
                parent=frame.winfo_toplevel(),
            ),
            finish,
            cancellable=True,
        )

    ctk.CTkButton(
        cf_worker_input, text="?", width=28, height=32,
        font=(theme.ui_font_family, 14), corner_radius=8,
        fg_color=theme.field_bg, hover_color=theme.field_border,
        text_color=theme.text_primary, border_width=1, border_color=theme.field_border,
        command=lambda: webbrowser.open(_get_doc_url("CfWorker")),
    ).pack(side="right")

    _cfworker_test_widget = ctk.CTkButton(
        cf_worker_row, text=t("button.test"), width=74, height=34,
        font=(theme.ui_font_family, 13), corner_radius=8,
        fg_color=theme.field_bg, hover_color=theme.field_border,
        text_color=theme.text_primary, border_width=1, border_color=theme.field_border,
        command=_on_cfworker_test,
    )
    _cfworker_test_widget.pack(side="right")

    def _sync_cfworker_entry(*_):
        state = "normal" if cfproxy_worker_enabled_var.get() else "disabled"
        cf_worker_entry.configure(state=state)
        _sync_cfworker_test_button()

    cfproxy_worker_enabled_var.trace_add("write", _sync_cfworker_entry)
    cfproxy_worker_domain_var.trace_add("write", _sync_cfworker_test_button)
    _sync_cfworker_entry()
    return cfproxy_worker_enabled_var, cfproxy_worker_domain_var


def _create_logging(ctk, frame, theme, cfg, default_config, no_secure_var):
    log_inner = create_config_section(ctk, frame, theme, t("section.logs"))

    verbose_var = ctk.BooleanVar(master=frame, value=cfg.get("verbose", False))
    verbose_cb = create_checkbox(ctk, log_inner, theme, t("label.verbose"), verbose_var)
    verbose_cb.pack(anchor="w", pady=(0, 6))
    attach_ctk_tooltip(verbose_cb, t("tip.verbose"))

    no_secure_cb = create_checkbox(ctk, log_inner, theme, t("label.no_secure"), no_secure_var)
    no_secure_cb.pack(anchor="w", pady=(0, 6))
    attach_ctk_tooltip(no_secure_cb, t("tip.no_secure"))

    adv_frame = ctk.CTkFrame(log_inner, fg_color="transparent")
    adv_frame.pack(fill="x")

    adv_rows = [
        (t("label.buf_kb"), "buf_kb", t("tip.buf_kb")),
        (t("label.pool_size"), "pool_size", t("tip.pool")),
        (t("label.log_max_mb"), "log_max_mb", t("tip.log_mb")),
    ]
    advanced_vars = {}
    for label_text, key, tip in adv_rows:
        col = ctk.CTkFrame(adv_frame, fg_color="transparent")
        col.pack(fill="x", pady=(0, 0 if key == "log_max_mb" else 5))
        adv_l = create_label(ctk, col, theme, label_text, size=11)
        adv_l.pack(anchor="w", pady=(0, 2))
        advanced_vars[key] = ctk.StringVar(master=frame, value=str(cfg.get(key, default_config[key])))
        adv_e = create_entry(
            ctk, col, theme, width=_INNER_W, height=32, radius=8,
            var=advanced_vars[key],
        )
        adv_e.pack(fill="x")
        attach_tooltip_to_widgets([adv_l, adv_e, col], tip)
    return verbose_var, advanced_vars


def _create_updates(ctk, frame, theme, cfg, default_config, on_update_click):
    upd_inner = create_config_section(ctk, frame, theme, t("section.updates"))
    check_updates_var = ctk.BooleanVar(
        master=frame, value=bool(cfg.get("check_updates", default_config.get("check_updates", True)))
    )
    upd_cb = create_checkbox(ctk, upd_inner, theme, t("label.check_updates"), check_updates_var)
    upd_cb.pack(anchor="w", pady=(0, 6))
    attach_ctk_tooltip(upd_cb, t("tip.check_updates"))
    auto_install_updates_var = ctk.BooleanVar(
        master=frame, value=bool(cfg.get("auto_install_updates", True))
    )
    automatic_cb = create_checkbox(
        ctk, upd_inner, theme, t("label.auto_install_updates"), auto_install_updates_var,
    )
    automatic_cb.pack(anchor="w", pady=(0, 6))
    create_label(
        ctk, upd_inner, theme, t("tip.auto_install_updates"), size=11,
        justify="left", wraplength=_INNER_W,
    ).pack(anchor="w", pady=(0, 10))

    status_label = create_label(ctk, upd_inner, theme, "", size=11,
                                justify="left", wraplength=_INNER_W)
    status_label.pack(anchor="w", pady=(0, 8))
    check_task = BackgroundTask(frame.winfo_toplevel())

    def check():
        if check_task.running or check_task.closed:
            return
        check_button.configure(state="disabled")
        status_label.configure(text=t("updates.status_checking"))
        check_task.start(
            lambda: run_check(__version__), lambda _: refresh(),
            lambda: check_button.configure(state="normal"),
        )

    check_button = ctk.CTkButton(
        upd_inner, text=t("button.check_updates"), height=32,
        font=(theme.ui_font_family, 13), corner_radius=8,
        fg_color=theme.field_bg, hover_color=theme.field_border,
        text_color=theme.text_primary, border_width=1, border_color=theme.field_border,
        command=check,
    )
    upd_btn_row = ctk.CTkFrame(upd_inner, fg_color="transparent")
    upd_btn_row.pack(fill="x")
    upd_btn_row.grid_columnconfigure(0, weight=1)
    release_button = ctk.CTkButton(
        upd_btn_row, text=t("button.open_release"), height=32,
        font=(theme.ui_font_family, 13), corner_radius=8,
        fg_color=theme.field_bg, hover_color=theme.field_border,
        text_color=theme.text_primary, border_width=1,
        border_color=theme.field_border,
    )
    release_button.grid(row=0, column=0, sticky="ew")
    update_button = ctk.CTkButton(
        upd_btn_row, text=t("button.update"), height=32,
        font=(theme.ui_font_family, 13, "bold"), corner_radius=8,
        fg_color=theme.accent, hover_color=theme.accent_hover,
        text_color=theme.accent_text, command=on_update_click,
    )

    def refresh():
        st = get_status()
        if st.get("error"):
            status = t("updates.status_error")
        elif not st.get("checked"):
            status = t("updates.status_pending")
        elif st.get("github_result") == "no_public_release" and not st.get("latest"):
            status = t("dashboard.update_no_release")
        elif st.get("has_update") and st.get("latest"):
            status = t("updates.status_available", latest=st["latest"], current=__version__)
        elif st.get("ahead_of_release") and st.get("latest"):
            status = t("updates.status_ahead", current=__version__, latest=st["latest"])
        else:
            status = t("updates.status_latest")
        if st.get("source") in {"github", "backup"}:
            status += "\n" + t("updates.source_server" if st["source"] == "backup"
                                else "updates.source_github")
        status_label.configure(text=status)
        rel_url = (st.get("html_url") or "").strip() or RELEASES_PAGE_URL
        release_button.configure(command=lambda: open_release_page(rel_url, parent=frame.winfo_toplevel()))
        can_update = bool(st.get("has_update") and on_update_click is not None)
        upd_btn_row.grid_columnconfigure(1, weight=int(can_update))
        release_button.grid_configure(padx=(0, 4) if can_update else 0)
        if can_update:
            update_button.grid(row=0, column=1, sticky="ew", padx=(4, 0))
        else:
            update_button.grid_remove()

    def sync_manual_check(*_):
        if check_updates_var.get():
            check_button.pack_forget()
        else:
            check_button.pack(fill="x", pady=(0, 8), before=upd_btn_row)

    check_updates_var.trace_add("write", sync_manual_check)
    sync_manual_check()
    refresh()
    return check_updates_var, auto_install_updates_var


def _create_autostart(ctk, frame, theme, show_autostart, autostart_value):
    autostart_var = None
    if show_autostart:
        sys_inner = create_config_section(ctk, frame, theme, t("section.windows_startup"), bottom_spacer=4)
        autostart_var = ctk.BooleanVar(master=frame, value=autostart_value)
        as_cb = create_checkbox(ctk, sys_inner, theme, t("label.autostart"), autostart_var)
        as_cb.pack(anchor="w", pady=(0, 4))
        as_hint = create_label(
            ctk, sys_inner, theme,
            t("label.autostart_hint"),
            size=11, justify="left", wraplength=_INNER_W,
        )
        as_hint.pack(anchor="w")
        attach_tooltip_to_widgets([as_cb, as_hint], t("tip.autostart"))
    return autostart_var


def validate_config_form(
    widgets: TrayConfigFormWidgets,
    default_config: dict,
    *,
    include_autostart: bool,
) -> Union[dict, str]:
    if widgets.helper_busy_var is not None and widgets.helper_busy_var.get():
        return t("ssh.busy")
    values = {
        "host": widgets.host_var.get(),
        "port": widgets.port_var.get(),
        "secret": widgets.secret_var.get(),
        "dc_ip": widgets.dc_textbox.get("1.0", "end"),
        "verbose": bool(widgets.verbose_var.get()),
    }
    for key, var in widgets.advanced_vars.items():
        values[key] = var.get()
    for key in (
        "check_updates", "auto_install_updates", "cfproxy", "h2", "cfproxy_user_domain_enabled",
        "cfproxy_worker_enabled", "no_secure", "helper_enabled",
    ):
        var = getattr(widgets, f"{key}_var")
        if var is not None:
            values[key] = bool(var.get())
    for key in ("cfproxy_user_domain", "cfproxy_worker_domain"):
        var = getattr(widgets, f"{key}_var")
        if var is not None:
            values[key] = var.get()
    if include_autostart:
        values["autostart"] = (
            bool(widgets.autostart_var.get())
            if widgets.autostart_var is not None else False
        )
    if widgets.appearance_var is not None:
        values["appearance"] = _appearance_to_cfg(widgets.appearance_var.get())
    if widgets.language_var is not None:
        values["language"] = language_from_label(widgets.language_var.get()).value
    validated = validate_settings(values, default_config)
    if isinstance(validated, str):
        return validated
    if widgets.helper_enabled_var is not None:
        helper_values = validate_helper_values(
            widgets.helper_config or {}, enabled=values.get("helper_enabled", False),
            mode=widgets.helper_mode_var.get(), host=widgets.helper_host_var.get(),
            port=widgets.helper_port_var.get(), fingerprint=widgets.helper_fingerprint_var.get(),
            token=widgets.helper_token_var.get(),
            registry=bool(widgets.helper_registry_var.get()) if widgets.helper_registry_var is not None else False,
        )
        if isinstance(helper_values, str):
            return helper_values
        validated.update(helper_values)
    return validated


