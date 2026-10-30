from __future__ import annotations

import sys

# Updater copies must dispatch before UI, portable migration, logging and mutexes.
from utils.update_installer import acknowledge_update, bootstrap_dispatch

_update_bootstrap_result = bootstrap_dispatch()
if _update_bootstrap_result is not None:
    raise SystemExit(_update_bootstrap_result)

import ctypes
from utils.windows_identity import set_application_identity

set_application_identity()

import os
import threading
import time
import webbrowser
import winreg

from pathlib import Path
from typing import Optional
from tkinter import TclError

try:
    import pyperclip
except ImportError:
    pyperclip = None

try:
    import pystray
except ImportError:
    pystray = None

try:
    import customtkinter as ctk
except ImportError:
    ctk = None

try:
    from PIL import Image
except ImportError:
    Image = None

from proxy import __version__, get_link_host

from utils.win32_theme import (
    is_windows_dark_theme, 
    apply_windows_dark_theme,
)
from utils.tray_common import (
    APP_NAME, CONFIG_FILE, DEFAULT_CONFIG, FIRST_RUN_MARKER, IS_FROZEN,
    acquire_lock, bootstrap, check_ipv6_warning, check_update_async, ctk_run_dialog,
    diagnostics_snapshot,
    ensure_ctk_thread, ensure_dirs, load_config, load_icon, log,
    proxy_running, quit_ctk, release_lock, restart_proxy,
    save_config, start_proxy, stop_proxy, tg_proxy_url,
)
from utils.update_check import find_asset, get_status, RELEASES_PAGE_URL
from utils.windows_update import apply_update, asset_name
from utils.windows_activation import InstanceActivation, request_activation
from ui.ctk_tray_ui import (
    install_tray_config_buttons, install_tray_config_form,
    populate_first_run_window, tray_settings_scroll_and_footer,
)
from ui.ctk_theme import (
    CONFIG_DIALOG_FRAME_PAD, CONFIG_DIALOG_SIZE, FIRST_RUN_SIZE,
    create_ctk_toplevel, ctk_theme_for_platform, main_content_frame,
    install_window_icon, present_ctk_dialog,
)
from ui.i18n import t
from ui.settings_dialog import SettingsDialog
from ui.dashboard import build_dashboard
from ui.external_links import open_release_page

_tray_icon: Optional[object] = None
_config: dict = {}
_exiting = False
_win_mutex_handle = None
_update_flow_lock = threading.Lock()
_dashboard_window = None
_dashboard_view = None
_dashboard_opening = False
_dashboard_logs_requested = False
_settings_window = None
_settings_widgets = None
_settings_opening = False
_settings_requested_page = None
_instance_activation = None
_ACTIVATION_EVENT = f"Local\\{APP_NAME}_ShowDashboard"

_ERROR_ALREADY_EXISTS = 183


def _window_exists(window) -> bool:
    """A recovered Tk interpreter cannot query windows owned by the old one."""
    try:
        return window is not None and bool(window.winfo_exists())
    except (TclError, RuntimeError):
        return False


def _dashboard_closed(done: threading.Event) -> None:
    global _dashboard_window, _dashboard_view
    _dashboard_window = None
    _dashboard_view = None
    log.info("Dashboard closed")
    done.set()


def _acquire_win_mutex() -> bool | None:
    global _win_mutex_handle
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        handle = kernel32.CreateMutexW(None, True, f"Local\\{APP_NAME}_SingleInstance")
        if kernel32.GetLastError() == _ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            return False
        if not handle:
            return None
        _win_mutex_handle = handle
        return True
    except Exception:
        return None


def _release_win_mutex() -> None:
    global _win_mutex_handle
    if _win_mutex_handle:
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.ReleaseMutex(ctypes.c_void_p(_win_mutex_handle))
            kernel32.CloseHandle(ctypes.c_void_p(_win_mutex_handle))
        except Exception:
            pass
        _win_mutex_handle = None

# win32 dialogs

_u32 = ctypes.windll.user32
_u32.MessageBoxW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
_u32.MessageBoxW.restype = ctypes.c_int

_MB_OK_ERR = 0x10
_MB_OK_INFO = 0x40
_MB_YESNO_Q = 0x24
_MB_YESNOCANCEL_Q = 0x23
_IDYES = 6
_IDNO = 7


def _show_error(text: str, title: Optional[str] = None) -> None:
    _u32.MessageBoxW(None, text, title or t("app.error_title"), _MB_OK_ERR)


def _show_info(text: str, title: Optional[str] = None) -> None:
    _u32.MessageBoxW(None, text, title or t("app.name"), _MB_OK_INFO)


def _ask_yes_no(text: str, title: Optional[str] = None) -> bool:
    return _u32.MessageBoxW(None, text, title or t("app.name"), _MB_YESNO_Q) == _IDYES


def update_ctk_form(
    text: str, title: Optional[str] = None, asset: Optional[dict] = None,
    release_url: Optional[str] = None,
) -> str:
    title = title or t("app.name")
    if ctk is None or not ensure_ctk_thread(ctk, _config.get("appearance", "auto")):
        if not asset:
            return "open" if _ask_yes_no(t("update.ask_open", version=get_status()["latest"]), title) else "close"
        result = _u32.MessageBoxW(None, text, title, _MB_YESNOCANCEL_Q)
        if result == _IDYES:
            _perform_update(asset)
        if result == _IDNO:
            return "open"
        return "close"

    result = {"value": "close"}

    def _build(done: threading.Event) -> None:
        theme = ctk_theme_for_platform()
        root = create_ctk_toplevel(
            ctk,
            title=title,
            width=310 if asset else 210,
            height=130 if asset else 100,
            theme=theme,
            topmost=True,
        )
        frame = main_content_frame(ctk, root, theme, padx=16, pady=14)

        ctk.CTkLabel(
            frame,
            text=text,
            justify="left",
            anchor="w",
            wraplength=270,
            font=(theme.ui_font_family, 12),
            text_color=theme.text_primary,
        ).pack(fill="x", pady=(0, 10))

        row = ctk.CTkFrame(frame, fg_color="transparent")
        row.pack(fill="x")

        status_label = ctk.CTkLabel(
            frame, text="", justify="left", anchor="w", wraplength=270,
            font=(theme.ui_font_family, 11), text_color=theme.text_secondary,
        )
        status_label.pack(fill="x", pady=(6, 0))

        btns: list = []

        def _set_status(msg: str) -> None:
            root.after(0, lambda: status_label.configure(text=msg))

        def _close_with(value: str) -> None:
            result["value"] = value
            root.destroy()
            done.set()

        def _on_update() -> None:
            for b in btns:
                b.configure(state="disabled")
            root.protocol("WM_DELETE_WINDOW", lambda: None)
            def _run():
                _perform_update(asset, set_status=_set_status)
                root.after(0, lambda: [b.configure(state="normal") for b in btns])
                root.after(0, lambda: root.protocol("WM_DELETE_WINDOW", lambda: _close_with("close")))
            threading.Thread(target=_run, daemon=True).start()

        if asset:
            btn_upd = ctk.CTkButton(
                row, text=t("button.update"), width=88, height=34,
                font=(theme.ui_font_family, 13), command=_on_update,
            )
            btn_upd.pack(side="left", padx=(0, 6))
            btns.append(btn_upd)
        btn_pg = ctk.CTkButton(
            row, text=t("button.page"), width=88, height=34,
            font=(theme.ui_font_family, 13), command=lambda: open_release_page(
                release_url or RELEASES_PAGE_URL, parent=root),
        )
        btn_pg.pack(side="left", padx=(0, 6))
        btns.append(btn_pg)
        btn_cl = ctk.CTkButton(
            row, text=t("button.close"), width=88, height=34,
            font=(theme.ui_font_family, 13),
            fg_color=theme.field_bg, hover_color=theme.field_border,
            text_color=theme.text_primary, border_width=1, border_color=theme.field_border,
            command=lambda: _close_with("close"),
        )
        btn_cl.pack(side="left")
        btns.append(btn_cl)

        root.protocol("WM_DELETE_WINDOW", lambda: _close_with("close"))

    ctk_run_dialog(_build)
    return result["value"]


def _perform_update(asset: dict, set_status=None) -> None:
    restarting = False

    def _step(msg: str) -> None:
        log.info("Update: %s", msg)
        if set_status:
            set_status(msg)

    def _before_restart() -> None:
        nonlocal restarting
        _step(t("update.restarting"))
        restarting = True
        stop_proxy()
        release_lock()
        _release_win_mutex()

    _step(t("update.downloading"))
    try:
        apply_update(asset, _before_restart)
    except Exception as exc:
        log.exception("Update failed")
        if restarting:
            mutex = _acquire_win_mutex()
            if mutex is True or mutex is None and acquire_lock():
                start_proxy(_config, _show_error)
        msg = t("update.error", msg=exc)
        if set_status:
            set_status(msg)
        else:
            _show_error(msg)
        return
    os._exit(0)


def _trigger_update_flow(icon=None, item=None, *, automatic=False) -> None:
    """Show the update dialog for an update already known to be available.

    Reused by the tray "Update" item and the settings dialog's "Update"
    button, so an update can still be started after the initial startup
    prompt was skipped/closed.
    """
    if not _update_flow_lock.acquire(blocking=False):
        return

    def _show() -> None:
        try:
            if _exiting:
                return
            st = get_status()
            if not st.get("has_update"):
                return
            if _tray_icon is not None:
                _tray_icon.menu = _build_menu()
            url = (st.get("html_url") or "").strip() or RELEASES_PAGE_URL
            ver = st.get("latest") or "?"
            asset = find_asset(asset_name()) if IS_FROZEN else None

            if automatic:
                if asset is not None:
                    _perform_update(asset)
                else:
                    log.warning("Automatic update has no verified asset for this build")
                return

            choice = update_ctk_form(
                t("update.available", version=ver),
                asset=asset,
                release_url=url,
            )
            if choice == "open":
                open_release_page(url, parent=None)
        except Exception as exc:
            log.warning("Update flow failed: %s", repr(exc))
        finally:
            _update_flow_lock.release()

    threading.Thread(target=_show, daemon=True, name="manual-update").start()


# autostart (registry)

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _supports_autostart() -> bool:
    return IS_FROZEN


def _autostart_command() -> str:
    return f'"{sys.executable}" --autostart'


def is_autostart_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_READ) as k:
            val, _ = winreg.QueryValueEx(k, APP_NAME)
        return str(val).strip() in (_autostart_command(), f'"{sys.executable}"')
    except (FileNotFoundError, OSError):
        return False


def set_autostart_enabled(enabled: bool) -> None:
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as k:
            if enabled:
                winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, _autostart_command())
            else:
                try:
                    winreg.DeleteValue(k, APP_NAME)
                except FileNotFoundError:
                    pass
    except OSError as exc:
        log.error("Failed to update autostart: %s", exc)
        _show_error(
            t("dialog.autostart_fail", error=exc)
        )


def _migrate_autostart_command() -> None:
    """Mark our existing startup entry as background-only; never enable a new one."""
    if not _supports_autostart():
        return
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            value, kind = winreg.QueryValueEx(key, APP_NAME)
            if kind == winreg.REG_SZ and str(value).strip() == f'"{sys.executable}"':
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, _autostart_command())
    except FileNotFoundError:
        pass
    except OSError:
        log.warning("Could not migrate the existing autostart command")


def _activate_existing_dashboard() -> None:
    if not _exiting:
        log.info("Opening dashboard from another launch")
        _on_show_dashboard()


# tray callbacks

def _on_open_in_telegram(icon=None, item=None) -> None:
    url = tg_proxy_url(_config)
    log.info("Opening proxy link in Telegram")
    try:
        if not webbrowser.open(url):
            raise RuntimeError
    except Exception:
        log.info("Browser open failed, copying to clipboard")
        if pyperclip is None:
            _show_error(
                t("dialog.open_tg_fail_manual", url=url)
            )
            return
        try:
            pyperclip.copy(url)
            _show_info(
                t("dialog.open_tg_fail_clipboard", url=url)
            )
        except Exception as exc:
            log.error("Clipboard copy failed: %s", exc)
            _show_error(t("dialog.copy_fail", error=exc))


def _on_copy_link(icon=None, item=None) -> None:
    url = tg_proxy_url(_config)
    log.info("Copying proxy link to clipboard")
    if pyperclip is None:
        _show_error(t("dialog.pyperclip_missing"))
        return
    try:
        pyperclip.copy(url)
    except Exception as exc:
        log.error("Clipboard copy failed: %s", exc)
        _show_error(t("dialog.copy_fail", error=exc))


def _on_restart(icon=None, item=None) -> None:
    threading.Thread(
        target=lambda: restart_proxy(_config, _show_error), daemon=True
    ).start()


def _on_edit_config(icon=None, item=None, *, initial_page="connection") -> None:
    threading.Thread(target=_edit_config_dialog, kwargs={"initial_page": initial_page},
                     daemon=True).start()


def _on_show_dashboard(icon=None, item=None, *, show_logs=False) -> None:
    def _show() -> None:
        if not ensure_ctk_thread(ctk, _config.get("appearance", "auto")):
            _show_error(t("dialog.ctk_missing"))
            return

        def _build(done: threading.Event) -> None:
            global _dashboard_window, _dashboard_view, _dashboard_opening, _dashboard_logs_requested
            if _dashboard_opening:
                # Widget construction can pump nested Tk events. Reserve the
                # in-progress dashboard before creating any widgets.
                _dashboard_logs_requested |= show_logs
                done.set()
                return
            if _window_exists(_dashboard_window):
                _dashboard_window.deiconify()
                _dashboard_window.lift()
                _dashboard_window.focus_force()
                if show_logs and _dashboard_view is not None:
                    _dashboard_view.show_logs()
                done.set()
                return
            _dashboard_opening = True
            _dashboard_logs_requested = show_logs
            root = None
            try:
                theme = ctk_theme_for_platform()
                root = ctk.CTkToplevel()
                install_window_icon(root)
                view = build_dashboard(
                    ctk, root, theme, _config, running=proxy_running,
                    on_telegram=_on_open_in_telegram,
                    on_settings=_on_edit_config,
                    on_restart=_on_restart,
                    on_stop=stop_proxy,
                    on_copy=_on_copy_link,
                    on_update=_trigger_update_flow,
                    on_routes=lambda: _on_edit_config(initial_page="routes"),
                    get_diagnostics_snapshot=lambda: diagnostics_snapshot(_config),
                    config_path=str(CONFIG_FILE),
                    on_close=lambda: _dashboard_closed(done),
                )
                if _dashboard_logs_requested:
                    view.show_logs()
            except Exception:
                log.exception("Dashboard construction failed")
                if root is not None:
                    try:
                        root.destroy()
                    except Exception as exc:
                        log.warning("Could not close incomplete dashboard (%s)", type(exc).__name__)
                _dashboard_window = None
                _dashboard_view = None
                done.set()
                _show_error(t("dialog.dashboard_failed"))
                return
            finally:
                _dashboard_opening = False
                _dashboard_logs_requested = False
            _dashboard_window = root
            _dashboard_view = view
            log.info("Dashboard ready")

        ctk_run_dialog(_build)

    threading.Thread(target=_show, daemon=True, name="dashboard-window").start()


def _on_open_logs(icon=None, item=None) -> None:
    _on_show_dashboard(show_logs=True)


def _on_exit(icon=None, item=None) -> None:
    global _exiting
    if _exiting:
        os._exit(0)
        return
    _exiting = True
    log.info("User requested exit")
    quit_ctk()
    threading.Thread(target=lambda: (time.sleep(3), os._exit(0)), daemon=True, name="force-exit").start()
    if icon:
        icon.stop()


# settings dialog

def _edit_config_dialog(*, initial_page="connection") -> None:
    if not ensure_ctk_thread(ctk, _config.get("appearance", "auto")):
        _show_error(t("dialog.ctk_missing"))
        return

    def _build(done: threading.Event) -> None:
        global _settings_window, _settings_widgets, _settings_opening, _settings_requested_page
        if _settings_opening:
            if initial_page == "routes":
                _settings_requested_page = "routes"
            done.set()
            return
        if _window_exists(_settings_window):
            present_ctk_dialog(_settings_window, owner=_dashboard_window)
            navigate = getattr(_settings_widgets, "select_page", None)
            if initial_page == "routes" and navigate is not None:
                navigate("routes")
            done.set()
            return
        _settings_opening = True
        _settings_requested_page = initial_page
        root = None
        try:
            # Capture values only after reserving the single editor. Parallel
            # forms with old values could overwrite a later saved configuration.
            cfg = dict(_config)
            cfg["autostart"] = is_autostart_enabled()
            theme = ctk_theme_for_platform()
            w, h = CONFIG_DIALOG_SIZE
            root = create_ctk_toplevel(
                ctk, title=t("app.settings_title"), width=w, height=h, theme=theme,
                topmost=False, resizable=True,
            )
            root.minsize(560, 560)
            fpx, fpy = CONFIG_DIALOG_FRAME_PAD
            frame = main_content_frame(ctk, root, theme, padx=fpx, pady=fpy)
            scroll, footer = tray_settings_scroll_and_footer(ctk, frame, theme)

            def _refresh_tray_menu() -> None:
                if _tray_icon is not None:
                    _tray_icon.menu = _build_menu()

            widgets = install_tray_config_form(
                ctk, scroll, theme, cfg, DEFAULT_CONFIG,
                show_autostart=_supports_autostart(),
                autostart_value=cfg.get("autostart", False),
                on_update_click=_trigger_update_flow,
                initial_page=initial_page,
            )

            def _finish() -> None:
                global _settings_window, _settings_widgets
                try:
                    root.destroy()
                finally:
                    if _settings_window is root:
                        _settings_window = _settings_widgets = None
                    done.set()

            dialog = SettingsDialog(
                ctk=ctk, root=root, widgets=widgets, config=_config,
                defaults=DEFAULT_CONFIG, persist=save_config,
                refresh_menu=_refresh_tray_menu, finish=_finish,
                restart=lambda config: restart_proxy(config, _show_error),
                include_autostart=_supports_autostart(),
                apply_autostart=set_autostart_enabled if _supports_autostart() else None,
                read_autostart=is_autostart_enabled if _supports_autostart() else None,
            )
            root.protocol("WM_DELETE_WINDOW", dialog.cancel)
            install_tray_config_buttons(ctk, footer, theme, on_save=dialog.save, on_cancel=dialog.cancel,
                                        busy_var=widgets.helper_busy_var)
            _settings_window, _settings_widgets = root, widgets
            navigate = getattr(widgets, "select_page", None)
            if _settings_requested_page == "routes" and navigate is not None:
                navigate("routes")
            present_ctk_dialog(root, owner=_dashboard_window)
        except Exception as exc:
            log.error("Settings dialog construction failed (%s)", type(exc).__name__)
            if root is not None:
                try:
                    root.destroy()
                except Exception:
                    pass
            _settings_window = _settings_widgets = None
            done.set()
            _show_error(t("dialog.settings_failed"))
        finally:
            _settings_opening = False
            _settings_requested_page = None

    ctk_run_dialog(_build)


# first run

def _show_first_run() -> None:
    ensure_dirs()
    if FIRST_RUN_MARKER.exists():
        return
    if not ensure_ctk_thread(ctk, _config.get("appearance", "auto")):
        FIRST_RUN_MARKER.touch()
        return

    host = _config.get("host", DEFAULT_CONFIG["host"])
    port = _config.get("port", DEFAULT_CONFIG["port"])
    secret = _config.get("secret", DEFAULT_CONFIG["secret"])

    def _build(done: threading.Event) -> None:
        theme = ctk_theme_for_platform()
        w, h = FIRST_RUN_SIZE
        root = create_ctk_toplevel(
            ctk, title=t("app.name"), width=w, height=h, theme=theme,
            topmost=False,
        )

        def on_done(open_tg: bool) -> None:
            FIRST_RUN_MARKER.touch()
            root.destroy()
            done.set()
            if open_tg:
                _on_open_in_telegram()

        populate_first_run_window(ctk, root, theme, host=host, port=port, secret=secret, on_done=on_done)

    ctk_run_dialog(_build)


# tray menu

def _build_menu():
    if pystray is None:
        return None
    host = _config.get("host", DEFAULT_CONFIG["host"])
    port = _config.get("port", DEFAULT_CONFIG["port"])
    link_host = get_link_host(host)
    items = [
        pystray.MenuItem(t("tray.dashboard"), _on_show_dashboard, default=True),
        pystray.MenuItem(t("tray.open_telegram", host=link_host, port=port), _on_open_in_telegram),
        pystray.MenuItem(t("tray.copy_link"), _on_copy_link),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(t("tray.restart"), _on_restart),
        pystray.MenuItem(t("tray.settings"), _on_edit_config),
        pystray.MenuItem(t("tray.logs"), _on_open_logs),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(t("tray.exit"), _on_exit),
    ]

    st = get_status()
    if st.get("has_update"):
        items[-2:-2] = [
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                t("tray.update", current=__version__, new=st.get("latest") or "?"),
                _trigger_update_flow,
            )
        ]
    return pystray.Menu(*items)


# entry point

def run_tray() -> None:
    global _tray_icon, _config

    _config = load_config()
    _migrate_autostart_command()

    if is_windows_dark_theme():
        apply_windows_dark_theme()

    bootstrap(_config)

    if pystray is None or Image is None or ctk is None:
        log.error("pystray, Pillow or customtkinter not installed; running in console mode")
        start_proxy(_config, _show_error)
        acknowledge_update()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            stop_proxy()
        return

    start_proxy(_config, _show_error)
    check_update_async(_config, lambda: _exiting, lambda version, url: _trigger_update_flow(
        automatic=bool(_config.get("auto_install_updates", True))))
    _show_first_run()
    check_ipv6_warning(_show_info)

    _tray_icon = pystray.Icon(APP_NAME, load_icon(), t("app.name"), menu=_build_menu())
    log.info("Tray icon running")
    if "--dashboard" in sys.argv:
        _on_show_dashboard()
    def _tray_ready(icon):
        icon.visible = True
        if _instance_activation is not None:
            _instance_activation.start(_activate_existing_dashboard)
        acknowledge_update()

    _tray_icon.run(setup=_tray_ready)

    stop_proxy()
    log.info("Tray app exited")


def main() -> None:
    global _instance_activation, _exiting
    if (mutex_result := _acquire_win_mutex()) is False or mutex_result is None and not acquire_lock():
        # Background sign-in startup must never interrupt the desktop.
        if "--autostart" not in sys.argv:
            try:
                activated = request_activation(_ACTIVATION_EVENT)
            except OSError:
                activated = False
            if not activated:
                # Compatibility with a running instance that has no activation event.
                _show_info(t("dialog.already_running"), os.path.basename(sys.argv[0]))
        return

    try:
        try:
            # Keep early activation requests until proxy/tray initialization ends.
            _instance_activation = InstanceActivation(_ACTIVATION_EVENT)
        except OSError:
            log.warning("Could not create the dashboard activation event")
        run_tray()
    finally:
        _exiting = True
        try:
            if _instance_activation is not None:
                _instance_activation.close()
        finally:
            _instance_activation = None
            release_lock()
            _release_win_mutex()


if __name__ == "__main__":
    main()
