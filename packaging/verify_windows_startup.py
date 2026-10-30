"""Exercise the frozen tray's startup and second-launch activation in isolation."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from utils.default_config import default_tray_config
from utils.windows_activation import _kernel32
from verify_update_chain import stop_owned


def until(predicate, *, timeout=20):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise TimeoutError("Frozen startup did not reach the expected state")
        time.sleep(.1)


def verify(exe: Path, output: Path, *, hold_seconds=0):
    output.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix="startup-", dir=output)).resolve()
    target = case / "TG Proxy startup test.exe"
    shutil.copy2(exe.resolve(strict=True), target)
    appdata, profile, temporary = (case / p for p in ("AppData", "Profile", "Temp"))
    settings = appdata / "TgWsProxy"
    for folder in (settings, profile, temporary):
        folder.mkdir(parents=True)
    with socket.socket() as free:
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
    config = default_tray_config()
    config.update(host="127.0.0.1", port=port, pool_size=0, dc_ip=[], cfproxy=False, h2=False,
                  cfproxy_user_domain_enabled=True, cfproxy_user_domain=["example.invalid"],
                  check_updates=False, auto_install_updates=False, autostart=False,
                  helper_enabled=False, helper_host="", helper_token_dpapi="", appearance="dark")
    (settings / "config.json").write_text(json.dumps(config), encoding="utf-8")
    for marker in (".first_run_done_mtproto", ".ipv6_warned"):
        (settings / marker).touch()
    env = dict(os.environ, APPDATA=str(appdata), LOCALAPPDATA=str(appdata), USERPROFILE=str(profile),
               TEMP=str(temporary), TMP=str(temporary))
    args = dict(cwd=case, env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    log = settings / "proxy.log"
    text = lambda: log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    api = _kernel32()

    def event_exists():
        handle = api.OpenEventW(0x0002, False, "Local\\TgWsProxy_ShowDashboard")
        if handle:
            api.CloseHandle(handle)
        return bool(handle)

    if event_exists():
        raise RuntimeError("A stable instance is active; isolated startup verification needs it stopped")
    first = subprocess.Popen([str(target), "--autostart"], **args)
    try:
        until(event_exists)
        # Launch the duplicate before readiness to cover the cold-start overlap.
        cold_duplicate = "Tray icon running" not in text()
        background = subprocess.Popen([str(target), "--autostart"], **args)
        assert background.wait(timeout=15) == 0, "Background duplicate must exit silently"
        until(lambda: "Tray icon running" in text())
        assert first.poll() is None
        assert "Dashboard ready" not in text(), "Background startup must remain in the tray"
        launches = [subprocess.Popen([str(target)] + (["--dashboard"] if i % 2 else []), **args)
                    for i in range(4)]
        assert all(p.wait(timeout=15) == 0 for p in launches), "Second launch displayed a blocking dialog"
        until(lambda: "Dashboard ready" in text())
        time.sleep(.5)
        assert text().count("Dashboard ready") == 1, "Multiple dashboard windows were constructed"
        assert "Traceback (most recent call last)" not in text()
        assert first.poll() is None, "Activation must retain the primary tray process"
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            pass
        result = dict(status="passed", exe=str(target), pid=first.pid, port=port,
                      cold_background_duplicate=cold_duplicate, silent_background=True, manual_launches=4,
                      single_dashboard=True, primary_retained=True, listener=True,
                      process_count_note="PyInstaller onefile uses a parent and child process")
        (output / "startup.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result), flush=True)
        deadline = time.monotonic() + hold_seconds
        while time.monotonic() < deadline and not (output / "startup.stop").exists():
            if first.poll() is not None:
                raise RuntimeError("Primary exited during native inspection")
            time.sleep(.1)
        return result
    finally:
        stop_owned(case)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--hold-seconds", type=int, default=0)
    options = parser.parse_args()
    verify(options.exe, options.output, hold_seconds=options.hold_seconds)
