"""Start the actual Windows executable with isolated, local-only settings.

    python packaging/verify_windows_exe.py --exe dist/TgWsProxy.exe

--keep-open leaves the verified process available for visual inspection until
the report's .stop sibling appears, or --hold-seconds elapses.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from utils.default_config import default_tray_config


def stop_process_tree(process):
    try:
        parent = psutil.Process(process.pid)
        owned = parent.children(recursive=True) + [parent]
    except psutil.NoSuchProcess:
        return
    for item in owned:
        try:
            item.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(owned, timeout=5)
    for item in alive:
        try:
            item.kill()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(alive, timeout=5)
    process.wait(timeout=5)


def verify(executable, *, report=None, keep_open=False, hold_seconds=180):
    executable = executable.resolve(strict=True)
    if report is not None:
        report = report.resolve()
        report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tg-proxy-exe-test-") as folder:
        root = Path(folder)
        appdata = root / "AppData"
        settings = appdata / "TgWsProxy"
        settings.mkdir(parents=True)
        profile = root / "Profile"
        profile.mkdir()
        temporary = root / "Temp"
        temporary.mkdir()
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        config = default_tray_config()
        config.update(
            host="127.0.0.1", port=port, pool_size=0, dc_ip=[],
            cfproxy=False, h2=False, check_updates=False, autostart=False,
            cfproxy_user_domain_enabled=True,
            cfproxy_user_domain=["example.invalid"],
            cfproxy_worker_enabled=False, cfproxy_worker_domain=[],
            helper_mode="direct", helper_host="", helper_token_dpapi="",
            language="ru", appearance="dark",
        )
        (settings / "config.json").write_text(json.dumps(config), encoding="utf-8")
        for marker in (".first_run_done_mtproto", ".ipv6_warned"):
            (settings / marker).touch()
        environment = os.environ.copy()
        environment.update(APPDATA=str(appdata), LOCALAPPDATA=str(appdata),
                           USERPROFILE=str(profile), TEMP=str(temporary), TMP=str(temporary))
        process = subprocess.Popen([str(executable), "--dashboard"],
                                   cwd=executable.parent, env=environment)
        log_path = settings / "proxy.log"
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                logs = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
                if "Dashboard construction failed" in logs or "CTk dialog failed" in logs:
                    raise RuntimeError(logs)
                if process.poll() is not None:
                    raise RuntimeError(f"Executable exited with code {process.returncode}\n{logs}")
                if "Dashboard ready" in logs:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError(f"Executable did not build its dashboard within 30 seconds\n{logs}")
            # Exercise the listener as well as the frozen UI; no upstream is configured.
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                # A bad MTProto handshake exercises the WARNING event path
                # without contacting an upstream or using any real secret.
                client.sendall(b"\x00" * 64)
                client.shutdown(socket.SHUT_WR)
            time.sleep(0.8)  # Includes CTk's delayed titlebar/icon callbacks.
            logs = log_path.read_text(encoding="utf-8", errors="replace")
            if "Traceback (most recent call last)" in logs:
                raise RuntimeError(logs)
            result = {"status": "passed", "exe": str(executable), "pid": process.pid,
                      "dashboard": True, "listener": True, "port": port,
                      "isolated_config": str(settings / "config.json")}
            if report is not None:
                report.write_text(json.dumps(result, indent=2), encoding="utf-8")
            print("PACKAGED EXE PASSED: dashboard, images, delayed callbacks and localhost listener", flush=True)
            if keep_open:
                if report is None:
                    raise ValueError("--keep-open requires --report")
                stop_file = report.with_suffix(".stop")
                print(f"Visual inspection ready; create {stop_file} to finish.", flush=True)
                deadline = time.monotonic() + hold_seconds
                while time.monotonic() < deadline and not stop_file.exists():
                    if process.poll() is not None:
                        break
                    time.sleep(0.1)
            return result
        finally:
            stop_process_tree(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=ROOT / "dist" / "TgWsProxy.exe")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep-open", action="store_true")
    parser.add_argument("--hold-seconds", type=int, default=180)
    arguments = parser.parse_args()
    if sys.platform != "win32":
        parser.error("This check runs the Windows executable on Windows")
    verify(arguments.exe, report=arguments.report, keep_open=arguments.keep_open,
           hold_seconds=arguments.hold_seconds)


if __name__ == "__main__":
    main()
