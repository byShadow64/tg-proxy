from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import socket as _socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from copy import deepcopy

import psutil

from proxy import __version__, get_link_host, parse_dc_ip_list, proxy_config, coerce_domain_list
from proxy.utils import SensitiveDataFormatter
from proxy.tg_ws_proxy import _run
from utils.default_config import default_tray_config
from utils.helper_config import effective_helper_mode, helper_is_enabled
from utils.diagnostics import diagnose_listen_error
from utils.logging_setup import (
    LOG_HANDLER_ROLE, apply_logging_verbosity, build_log_handler, log_size_limit,
)
from utils.live_logs import live_logs

log = logging.getLogger("tg-ws-tray")

APP_NAME = "TgWsProxy"
PORTABLE_DIR_NAME = "TgWsProxy_data"


def _standard_app_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_NAME


def _exe_dir() -> Optional[Path]:
    try:
        base = getattr(sys, "frozen", False) and sys.executable or sys.argv[0]
    except Exception:
        return None
    if not base:
        return None
    try:
        p = Path(base).resolve(strict=False)
    except OSError:
        p = Path(os.path.realpath(base))
    return p.parent if p.is_file() else p


def _detect_portable() -> Optional[Path]:
    exe_dir = _exe_dir()
    if exe_dir is None:
        return None
    portable_dir = exe_dir / PORTABLE_DIR_NAME
    if "--portable" in sys.argv:
        try:
            portable_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.warning("Cannot create portable dir %s: %s", portable_dir, repr(exc))
            return None
    if portable_dir.is_dir():
        _migrate_into_portable(portable_dir)
        return portable_dir
    return None


def _migrate_into_portable(portable_dir: Path) -> None:
    try:
        if any(portable_dir.iterdir()):
            return
    except OSError:
        return
    std = _standard_app_dir()
    if not std.exists():
        return
    try:
        for src in std.iterdir():
            if ".log" in src.name:
                continue
            dst = portable_dir / src.name
            try:
                if not src.is_dir():
                    shutil.copy2(src, dst)
            except OSError as exc:
                log.warning("Portable migration: skip %s: %s", src.name, repr(exc))
    except OSError as exc:
        log.warning("Portable migration failed: %s", repr(exc))


def _app_dir() -> Path:
    return _detect_portable() or _standard_app_dir()


APP_DIR = _app_dir()
CONFIG_FILE = APP_DIR / "config.json"
LOG_FILE = APP_DIR / "proxy.log"
FIRST_RUN_MARKER = APP_DIR / ".first_run_done_mtproto"
IPV6_WARN_MARKER = APP_DIR / ".ipv6_warned"

DEFAULT_CONFIG: Dict[str, Any] = default_tray_config()

IS_FROZEN = bool(getattr(sys, "frozen", False))


def ensure_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)


# single-instance lock

_lock_file_path: Optional[Path] = None


def _same_process(meta: dict, proc: psutil.Process) -> bool:
    try:
        lock_ct = float(meta.get("create_time", 0.0))
        if lock_ct > 0 and abs(lock_ct - proc.create_time()) > 1.0:
            return False
    except Exception:
        return False
    if IS_FROZEN:
        try:
            return Path(proc.exe()).resolve() == Path(sys.executable).resolve()
        except (OSError, psutil.Error):
            return False
    return False


def acquire_lock() -> bool:
    global _lock_file_path
    ensure_dirs()
    for f in list(APP_DIR.glob("*.lock")):
        try:
            pid = int(f.stem)
        except Exception:
            try:
                f.unlink(missing_ok=True)
            except OSError:
                pass
            continue
        meta: dict = {}
        try:
            raw = f.read_text(encoding="utf-8").strip()
            if raw:
                meta = json.loads(raw)
        except Exception:
            pass
        is_running = False
        try:
            is_running = _same_process(meta, psutil.Process(pid))
        except Exception:
            pass
        if is_running:
            return False
        try:
            f.unlink(missing_ok=True)
        except OSError:
            pass

    lock_file = APP_DIR / f"{os.getpid()}.lock"
    try:
        proc = psutil.Process(os.getpid())
        lock_file.write_text(
            json.dumps({"create_time": proc.create_time()}, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        try:
            lock_file.touch()
        except Exception:
            pass
    _lock_file_path = lock_file
    return True


def release_lock() -> None:
    global _lock_file_path
    if _lock_file_path:
        try:
            _lock_file_path.unlink(missing_ok=True)
        except Exception:
            pass
        _lock_file_path = None


# config

def _apply_ui_language(cfg: dict) -> None:
    from ui.i18n import set_language

    set_language(cfg.get("language", DEFAULT_CONFIG["language"]))


def _backup_once(path: Path, suffix: str) -> Optional[Path]:
    """Keep a byte-for-byte copy before any config migration or repair."""
    backup = path.with_name(path.name + suffix)
    if backup.exists():
        return backup
    try:
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)
        return backup
    except OSError as exc:
        log.warning("Could not back up config %s (%s)", path, type(exc).__name__)
        return None


def _read_json_object(path: Path) -> Optional[dict]:
    try:
        with path.open("r", encoding="utf-8") as f:
            value = json.load(f)
        if not isinstance(value, dict):
            raise ValueError("configuration root must be an object")
        return value
    except Exception as exc:
        log.warning("Could not read config %s (%s)", path, type(exc).__name__)
        return None


def _migrate_legacy_config(data: dict, legacy_path: Path) -> bool:
    """Import fields from the retired ~/.tg-proxy schema without overwrites."""
    if not legacy_path.is_file():
        return False
    old = _read_json_object(legacy_path)
    _backup_once(legacy_path, ".pre-upstream.bak")
    if old is None:
        return False

    mapping = {
        "host": "host", "port": "port", "dc_ip": "dc_ip",
        "secret": "secret", "verbose": "verbose", "autostart": "autostart",
        "buffer_kb": "buf_kb", "helper_host": "helper_host",
        "helper_port": "helper_port", "use_helper": "use_helper",
    }
    changed = False
    legacy_helper_imported = False
    for old_key, new_key in mapping.items():
        if old_key not in old:
            continue
        if old_key == "use_helper":
            if old[old_key] and old.get("helper_host"):
                if "helper_mode" not in data:
                    data["helper_mode"] = "legacy"
                    changed = True
                    legacy_helper_imported = True
                if "helper_host" not in data:
                    data["helper_host"] = old.get("helper_host", "")
                    changed = True
                if "helper_port" not in data:
                    data["helper_port"] = old.get("helper_port", 8443)
                    changed = True
            elif "helper_mode" not in data:
                data["helper_mode"] = "direct"
                changed = True
            continue
        if new_key not in data:
            data[new_key] = old[old_key]
            changed = True

    if legacy_helper_imported:
        log.warning(
            "Imported an old helper configuration in temporary legacy mode. "
            "Legacy helper traffic is unencrypted; configure TLS pinning in the dashboard."
        )
        changed = True
    return changed


def load_config() -> dict:
    ensure_dirs()
    data: dict = {}
    if CONFIG_FILE.exists():
        loaded = _read_json_object(CONFIG_FILE)
        if loaded is None:
            _backup_once(CONFIG_FILE, ".corrupt.bak")
        else:
            data = loaded

    legacy_path = Path.home() / ".tg-proxy" / "config.json"
    migrated = _migrate_legacy_config(data, legacy_path)
    if "helper_enabled" not in data:
        # Resolve the old mode before default False is merged, preserving
        # existing TLS/legacy users and an explicit switch saved by new clients.
        data["helper_enabled"] = helper_is_enabled(data)
        migrated = True
    if "cfproxy_user_domain_enabled" not in data:
        data["cfproxy_user_domain_enabled"] = bool(
            coerce_domain_list(data.get("cfproxy_user_domain"))
        )
    if "cfproxy_worker_enabled" not in data:
        data["cfproxy_worker_enabled"] = bool(
            coerce_domain_list(data.get("cfproxy_worker_domain"))
        )
    cfg = deepcopy(DEFAULT_CONFIG)
    cfg.update(data)
    _apply_ui_language(cfg)
    if migrated or not CONFIG_FILE.exists() or not data:
        save_config(cfg)
    return cfg


def save_config(cfg: dict) -> None:
    ensure_dirs()
    fd, temporary = tempfile.mkstemp(prefix="config-", suffix=".tmp", dir=str(APP_DIR))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, CONFIG_FILE)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


# logging

_LOG_FMT_FILE = "%(asctime)s  %(levelname)-5s  %(name)s  %(message)s"
_LOG_FMT_CONSOLE = "%(asctime)s  %(levelname)-5s  %(message)s"


def setup_logging(verbose: bool = False, log_max_mb: float = 5) -> None:
    ensure_dirs()
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    setattr(live_logs, LOG_HANDLER_ROLE, "live")
    live_logs.setLevel(level)
    live_logs.setFormatter(SensitiveDataFormatter(
        _LOG_FMT_FILE, datefmt="%Y-%m-%d %H:%M:%S",
        secrets=lambda: (proxy_config.secret, proxy_config.helper_token),
    ))
    if live_logs not in root.handlers:
        root.addHandler(live_logs)

    log_path = os.path.normcase(os.path.abspath(str(LOG_FILE)))
    fh = next((handler for handler in root.handlers
               if getattr(handler, LOG_HANDLER_ROLE, None) == "file"
               and os.path.normcase(handler.baseFilename) == log_path), None)
    if fh is None:
        fh = build_log_handler(str(LOG_FILE), log_max_mb=log_max_mb, backups=1)
        setattr(fh, LOG_HANDLER_ROLE, "file")
    else:
        fh.acquire()
        try:
            fh.maxBytes = log_size_limit(log_max_mb)
            fh.backupCount = max(1, fh.backupCount)
        finally:
            fh.release()
    fh.setLevel(level)
    fh.setFormatter(SensitiveDataFormatter(
        _LOG_FMT_FILE, datefmt="%Y-%m-%d %H:%M:%S",
        secrets=lambda: (proxy_config.secret, proxy_config.helper_token),
    ))
    root.addHandler(fh)

    ch = None
    if not IS_FROZEN:
        ch = next((handler for handler in root.handlers
                   if getattr(handler, LOG_HANDLER_ROLE, None) == "console"
                   and handler.stream is sys.stdout), None)
        if ch is None:
            ch = logging.StreamHandler(sys.stdout)
            setattr(ch, LOG_HANDLER_ROLE, "console")
        ch.setLevel(level)
        ch.setFormatter(SensitiveDataFormatter(
            _LOG_FMT_CONSOLE, datefmt="%H:%M:%S",
            secrets=lambda: (proxy_config.secret, proxy_config.helper_token),
        ))
        root.addHandler(ch)

    # Reconfiguration must not accumulate file streams or duplicate records.
    # Keep the live handler itself so its existing bounded history survives.
    retained = {live_logs, fh, ch}
    for handler in root.handlers[:]:
        if getattr(handler, LOG_HANDLER_ROLE, None) in ("live", "file", "console") and handler not in retained:
            root.removeHandler(handler)
            handler.close()
    apply_logging_verbosity(verbose)


# icon

def make_icon_image(size: int = 64, *, color: Optional[Tuple[int, ...]] = None):
    if color is None:
        from ui.icons import app_icon
        return app_icon(size)
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    margin = 2
    draw.ellipse([margin, margin, size - margin, size - margin], fill=color)

    for path in _font_paths():
        try:
            font = ImageFont.truetype(path, size=int(size * 0.55))
            break
        except Exception:
            continue
    else:
        font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), "T", font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text(
        ((size - tw) // 2 - bbox[0], (size - th) // 2 - bbox[1]),
        "T",
        fill=(255, 255, 255, 255),
        font=font,
    )
    return img


def _font_paths():
    if sys.platform == "win32":
        return ["arial.ttf"]
    if sys.platform == "darwin":
        return ["/System/Library/Fonts/Helvetica.ttc"]
    return [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
    ]


def load_icon():
    from PIL import Image

    icon_path = Path(__file__).parents[1] / "icon.ico"
    if icon_path.exists():
        try:
            return Image.open(str(icon_path))
        except Exception:
            pass
    return make_icon_image(64)


# proxy lifecycle

_proxy_thread: Optional[threading.Thread] = None
_async_stop: Optional[Tuple[asyncio.AbstractEventLoop, asyncio.Event]] = None
_proxy_stop_requested: Optional[threading.Event] = None
_proxy_lifecycle_lock = threading.RLock()
_proxy_diagnostics_state = (0, None)
PROXY_STOP_TIMEOUT = 5.0


def _run_proxy_thread(show_error: Callable[[str], None],
                      stop_requested: Optional[threading.Event] = None) -> None:
    global _async_stop

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    stop_ev = asyncio.Event()
    _async_stop = (loop, stop_ev)

    try:
        # Stop may arrive before this thread has published its asyncio event.
        if stop_requested is None or not stop_requested.is_set():
            loop.run_until_complete(_run(stop_event=stop_ev))
    except Exception as exc:
        log.error("Proxy thread crashed: %s", repr(exc))
        msg, diagnose_called = diagnose_listen_error(exc)
        if msg:
            show_error(msg)
        if diagnose_called:
            diagnose_called()
    finally:
        pending = [
            task for task in asyncio.all_tasks(loop)
            if not task.done()
        ]
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(
                *pending, return_exceptions=True
            ))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        if _async_stop is not None and _async_stop[0] is loop:
            _async_stop = None


def apply_proxy_config(cfg: dict) -> bool:
    global _proxy_diagnostics_state
    dc_ip_list = cfg.get("dc_ip", DEFAULT_CONFIG["dc_ip"])
    try:
        dc_redirects = parse_dc_ip_list(dc_ip_list)
    except ValueError as e:
        log.error("Bad config dc_ip: %s", e)
        return False

    pc = proxy_config
    pc.port = cfg.get("port", DEFAULT_CONFIG["port"])
    pc.host = cfg.get("host", DEFAULT_CONFIG["host"])
    pc.secret = cfg.get("secret", DEFAULT_CONFIG["secret"])
    pc.dc_redirects = dc_redirects
    pc.buffer_size = max(4, cfg.get("buf_kb", DEFAULT_CONFIG["buf_kb"])) * 1024
    pc.pool_size = max(0, cfg.get("pool_size", DEFAULT_CONFIG["pool_size"]))
    pc.fallback_cfproxy = cfg.get("cfproxy", DEFAULT_CONFIG["cfproxy"])
    pc.cfproxy_h2_media = cfg.get("h2", DEFAULT_CONFIG["h2"])
    cfproxy_user_domains = coerce_domain_list(
        cfg.get("cfproxy_user_domain", DEFAULT_CONFIG["cfproxy_user_domain"])
    )
    cfproxy_worker_domains = coerce_domain_list(
        cfg.get("cfproxy_worker_domain", DEFAULT_CONFIG["cfproxy_worker_domain"])
    )
    pc.cfproxy_user_domains = (
        cfproxy_user_domains
        if cfg.get("cfproxy_user_domain_enabled", bool(cfproxy_user_domains))
        else []
    )
    pc.cfproxy_worker_domains = (
        cfproxy_worker_domains
        if cfg.get("cfproxy_worker_enabled", bool(cfproxy_worker_domains))
        else []
    )
    pc.force_test_dc = cfg.get("force_test_dc", DEFAULT_CONFIG["force_test_dc"])
    pc.disable_secure = cfg.get("no_secure", DEFAULT_CONFIG["no_secure"])
    pc.helper_mode = effective_helper_mode(cfg)
    pc.helper_host = str(cfg.get("helper_host", "")).strip()
    try:
        helper_port = int(cfg.get("helper_port", 8444) or 8444)
    except (TypeError, ValueError):
        helper_port = 8444 if pc.helper_mode == "tls-pin" else 8443
    pc.helper_port = helper_port if 1 <= helper_port <= 65535 else (
        8444 if pc.helper_mode == "tls-pin" else 8443
    )
    pc.helper_fingerprint = str(cfg.get("helper_fingerprint", "")).strip()
    pc.helper_token = ""
    pc.helper_registry = cfg.get("helper_registry") is True and pc.helper_mode == "tls-pin"
    if pc.helper_mode == "tls-pin" and not pc.helper_registry and cfg.get("helper_token_dpapi"):
        try:
            from utils.secure_storage import unprotect_token
            pc.helper_token = unprotect_token(cfg["helper_token_dpapi"])
        except Exception as exc:
            log.warning("Unable to unlock helper token (%s)", type(exc).__name__)
    # Publish a complete independent copy. Dashboard polling must never wait
    # on the lifecycle lock while stop_proxy joins the running worker.
    generation, _ = _proxy_diagnostics_state
    _proxy_diagnostics_state = (generation + 1, deepcopy(pc))
    return True


def start_proxy(cfg: dict, on_error: Callable[[str], None]) -> bool:
    global _proxy_thread, _proxy_stop_requested
    with _proxy_lifecycle_lock:
        if _proxy_thread and _proxy_thread.is_alive():
            log.info("Proxy already running")
            return False

        if not apply_proxy_config(cfg):
            from ui.i18n import t
            on_error(t("error.dc_config"))
            return False

        pc = proxy_config
        log.info("Starting proxy on %s:%d ...", pc.host, pc.port)
        _proxy_stop_requested = threading.Event()
        _proxy_thread = threading.Thread(
            target=_run_proxy_thread, args=(on_error, _proxy_stop_requested),
            daemon=True, name="proxy",
        )
        try:
            _proxy_thread.start()
        except BaseException:
            _proxy_thread = _proxy_stop_requested = None
            raise
        return True


def stop_proxy() -> bool:
    """Wait for a confirmed shutdown; call from a background UI action."""
    global _proxy_thread, _async_stop, _proxy_stop_requested, _proxy_diagnostics_state
    with _proxy_lifecycle_lock:
        generation, active = _proxy_diagnostics_state
        _proxy_diagnostics_state = (generation + 1, active)
        thread = _proxy_thread
        if _proxy_stop_requested is not None:
            _proxy_stop_requested.set()
        control = _async_stop
        if control is not None:
            loop, stop_ev = control
            try:
                loop.call_soon_threadsafe(stop_ev.set)
            except RuntimeError:
                # The worker may have closed its loop just before this call.
                pass
        if thread is not None and thread.is_alive():
            if thread is threading.current_thread():
                return False
            thread.join(timeout=PROXY_STOP_TIMEOUT)
            if thread.is_alive():
                log.warning("Proxy thread did not stop within timeout; "
                            "port may still be in use")
                return False
        _proxy_thread = _async_stop = _proxy_stop_requested = None
        log.info("Proxy stopped")
        return True


def restart_proxy(cfg: dict, on_error: Callable[[str], None]) -> bool:
    with _proxy_lifecycle_lock:
        log.info("Restarting proxy...")
        if not stop_proxy():
            return False
        return start_proxy(cfg, on_error)


def proxy_running() -> bool:
    # Dashboard polling must stay responsive while stop_proxy waits in join().
    thread = _proxy_thread
    return bool(thread and thread.is_alive())


def diagnostics_snapshot(config: dict):
    """Capture applied routes without changing config or blocking the Tk loop."""
    from utils.connection_diagnostics import make_snapshot

    generation, active = _proxy_diagnostics_state
    running = proxy_running()
    if running and active is not None and not active.cfproxy_user_domains:
        from proxy.balancer import balancer

        # Copy only the catalog; never invoke its domain-selection methods.
        active = deepcopy(active)
        active.cfproxy_user_domains = list(balancer.domains)
    return make_snapshot(
        deepcopy(config), running=running, generation=generation,
        active=active if running else None,
    )


def tg_proxy_url(cfg: dict) -> str:
    host = cfg.get("host", DEFAULT_CONFIG["host"])
    port = cfg.get("port", DEFAULT_CONFIG["port"])
    secret = cfg.get("secret", DEFAULT_CONFIG["secret"])
    link_host = get_link_host(host)
    return f"tg://proxy?server={link_host}&port={port}&secret=dd{secret}"


def _has_ipv6() -> bool:
    try:
        for addr in _socket.getaddrinfo(_socket.gethostname(), None, _socket.AF_INET6):
            ip = addr[4][0]
            if ip and not ip.startswith("::1") and not ip.startswith("fe80::1"):
                return True
    except Exception:
        pass
    try:
        s = _socket.socket(_socket.AF_INET6, _socket.SOCK_STREAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except Exception:
        return False


def check_ipv6_warning(show_info: Callable[[str, str], None]) -> None:
    ensure_dirs()
    if IPV6_WARN_MARKER.exists() or not _has_ipv6():
        return
    IPV6_WARN_MARKER.touch()
    from ui.i18n import t

    threading.Thread(
        target=lambda: show_info(t("ipv6.warning"), t("app.name")),
        daemon=True,
    ).start()


# update check

def check_update_async(
    cfg: dict,
    is_exiting: Callable[[], bool],
    on_update: Callable[[str, str], None],
    *, interval: float = 3600,
) -> None:
    """Check on startup and periodically while the application is running.

    on_update(version, release_page_url) is called from the worker thread
    when a newer version is available.
    """
    if not cfg.get("check_updates", True):
        return

    def _work() -> None:
        if is_exiting() or not cfg.get("check_updates", True):
            return
        try:
            from utils.update_check import RELEASES_PAGE_URL, get_status, run_check

            run_check(__version__)
            st = get_status()
            if not st.get("has_update") or is_exiting():
                return
            on_update(
                st.get("latest") or "?",
                (st.get("html_url") or "").strip() or RELEASES_PAGE_URL,
            )
        except Exception as exc:
            log.warning("Update check failed: %s", repr(exc))
        finally:
            if not is_exiting() and cfg.get("check_updates", True):
                timer = threading.Timer(max(60, interval), _work)
                timer.daemon = True
                timer.start()

    def _initial() -> None:
        time.sleep(1.5)
        _work()

    threading.Thread(target=_initial, daemon=True, name="update-check").start()


def maybe_notify_update(
    cfg: dict,
    is_exiting: Callable[[], bool],
    ask_open: Callable[[str, str], bool],
) -> None:
    """Check for updates and offer to open the release page."""
    def _on_update(version: str, url: str) -> None:
        import webbrowser

        from ui.i18n import t

        if ask_open(t("update.ask_open", version=version), t("app.update_title")):
            webbrowser.open(url)

    check_update_async(cfg, is_exiting, _on_update)


# ctk thread (windows / linux)

_ctk_root: Any = None
_ctk_root_ready = threading.Event()
_ctk_root_lock = threading.Lock()
_ctk_root_thread: Optional[threading.Thread] = None


def ensure_ctk_thread(ctk: Any, mode: str = "auto") -> bool:
    global _ctk_root, _ctk_root_thread
    if ctk is None:
        return False

    def _run():
        global _ctk_root, _ctk_root_thread
        from ui.ctk_theme import (apply_ctk_appearance, install_tkinter_variable_del_guard,
                                  install_window_icon)

        root = None
        try:
            install_tkinter_variable_del_guard()
            apply_ctk_appearance(ctk, mode)
            root = ctk.CTk()
            install_window_icon(root, default=True)
            root.withdraw()
            with _ctk_root_lock:
                _ctk_root = root
                _ctk_root_ready.set()
            root.mainloop()
        except Exception as exc:
            log.warning("CTk root initialization failed (%s)", type(exc).__name__)
        finally:
            if root is not None:
                try:
                    root.destroy()
                except Exception:
                    pass
            with _ctk_root_lock:
                _ctk_root = None
                _ctk_root_thread = None
                # Wake callers after a failed attempt as well. A non-None root
                # distinguishes successful readiness from failed completion.
                _ctk_root_ready.set()

    with _ctk_root_lock:
        if _ctk_root_ready.is_set() and _ctk_root is not None:
            return True
        if _ctk_root_thread is None or not _ctk_root_thread.is_alive():
            _ctk_root = None
            _ctk_root_ready.clear()
            _ctk_root_thread = threading.Thread(target=_run, daemon=True, name="ctk-root")
            try:
                _ctk_root_thread.start()
            except RuntimeError:
                _ctk_root_thread = None
                _ctk_root_ready.set()
                log.warning("CTk root thread could not start")
    _ctk_root_ready.wait(timeout=5.0)
    with _ctk_root_lock:
        return _ctk_root_ready.is_set() and _ctk_root is not None


def ctk_run_dialog(build_fn: Callable[[threading.Event], None]) -> None:
    if _ctk_root is None:
        return
    done = threading.Event()

    def _invoke():
        try:
            build_fn(done)
        except Exception:
            log.exception("CTk dialog failed")
            done.set()

    _ctk_root.after(0, _invoke)
    done.wait()
    import gc
    gc.collect()


def quit_ctk() -> None:
    if _ctk_root is not None:
        try:
            _ctk_root.after(0, _ctk_root.quit)
        except Exception:
            pass


# common bootstrap

def bootstrap(cfg: dict) -> None:
    save_config(cfg)
    if LOG_FILE.exists():
        try:
            LOG_FILE.unlink()
        except Exception:
            pass
    setup_logging(
        cfg.get("verbose", False),
        log_max_mb=cfg.get("log_max_mb", DEFAULT_CONFIG["log_max_mb"]),
    )
    log.info("TG Proxy версия %s starting", __version__)
    # Config migrations retain unknown fields. They may contain credentials
    # from older versions or external tools, so never dump the whole object.
    log.info("Config loaded; verbose=%s, helper mode=%s",
             cfg.get("verbose") is True, effective_helper_mode(cfg))
    log.info("Log file: %s", LOG_FILE)
