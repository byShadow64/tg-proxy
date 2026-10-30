"""Prepare a verified update, then hand replacement to a private executable."""
from __future__ import annotations

import secrets
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Callable, Optional

from utils import update_installer as installer
from utils import update_progress
from utils.update_check import download_release_asset

_prepare_lock = threading.Lock()


def asset_name() -> Optional[str]:
    # Use the running build, including x86/x64 emulation and renamed executables.
    target = sysconfig.get_platform()
    if target == "win-arm64":
        return "TgWsProxy_windows_arm64.exe"
    if target == "win32":
        return "TgWsProxy_windows_7_32bit.exe"
    if target == "win-amd64":
        return "TgWsProxy_windows_7_64bit.exe" if sys.version_info < (3, 9) else "TgWsProxy_windows.exe"
    return None


def _wait_ready(stage, process, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            (stage / "state.json").lstat()
        except FileNotFoundError:
            # A onefile helper needs time to unpack before it can publish its
            # first record. Only absence is transient; invalid records fail.
            pass
        else:
            state = installer._read_json(stage / "state.json")
            if state.get("stage") == "ready" and installer.process_alive(state["helper"]):
                return
            if state.get("stage") in ("failed", "cancelled", "rollback_failed"):
                raise OSError("The update helper could not prepare the installation")
        if process.poll() is not None:
            raise OSError("The update helper exited before it was ready")
        time.sleep(.05)
    raise TimeoutError("The update helper did not become ready")


def _cancel_and_clean(stage, token, process):
    (stage / "cancel").touch(exist_ok=True)
    if process is not None:
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            return  # Never delete files underneath a still-running helper.
    plan_path = stage / "plan.json"
    if plan_path.exists() and (stage / "state.json").exists():
        with suppress(OSError, ValueError, KeyError):
            installer.cleanup_update(plan_path, token, timeout=2)
        return
    # No helper was started; these paths have been created only by this call.
    for name in installer._FILES:
        with suppress(OSError):
            (stage / name).unlink(missing_ok=True)
    with suppress(OSError):
        stage.rmdir()
    installer.release_install_lock({"_stage": stage, "token": token})


def apply_update(asset: dict, before_restart: Callable[[], None]) -> None:
    """Prepare a helper before asking the application to release locks and exit.

    The executable is still unchanged when this returns. A separate process
    waits for this application, replaces the file and requires a startup ACK.
    """
    if not _prepare_lock.acquire(blocking=False):
        raise installer.UpdateBusyError("An update installation is already running")
    stage, process, downloaded = None, None, None
    run_id, token = None, ""
    try:
        if update_progress.get_progress()["active"]:
            raise installer.UpdateBusyError("An update installation is already running")
        run_id = update_progress.begin(asset.get("version", ""))
        token = secrets.token_hex(32)
        if not getattr(sys, "frozen", False):
            raise ValueError("Automatic installation requires a packaged executable")
        exe = Path(sys.executable).absolute()
        installer._ordinary(exe, required=True)
        if exe.resolve() != exe or exe.suffix.lower() != ".exe":
            raise ValueError("Automatic installation requires an ordinary executable")
        # Same-volume preparation proves writability without requesting
        # elevation and keeps executable replacement an atomic rename.
        stage = Path(tempfile.mkdtemp(prefix=installer.STAGING_PREFIX, dir=str(exe.parent)))
        fixed = exe.parent / (installer.STAGING_PREFIX + secrets.token_hex(16))
        stage.rename(fixed)
        stage = fixed
        with suppress(OSError):
            stage.chmod(0o700)
        installer.acquire_install_lock(exe.parent, token, stage)
        downloaded, actual_asset = download_release_asset(asset, stage, suffix=".exe",
            progress=lambda count, total: update_progress.set_download(run_id, count, total),
            on_verifying=lambda: update_progress.set_phase(run_id, "verifying"),
            on_candidate=lambda candidate: update_progress.start_download(
                run_id, candidate.get("version", ""), candidate.get("size")))
        downloaded = Path(downloaded).absolute()
        if downloaded.parent != stage:
            raise ValueError("The download escaped its update workspace")
        update_progress.set_phase(run_id, "verifying")
        digest = installer.verify_payload(downloaded, actual_asset.get("digest"), actual_asset.get("size"))
        downloaded.replace(stage / "payload.exe")
        downloaded = None
        old_digest = installer.file_digest(exe)
        shutil.copyfile(exe, stage / "helper.exe")
        installer.verify_payload(stage / "helper.exe", old_digest)
        plan = {
            "schema": 1, "token": token, "target": exe.name, "created": time.time(),
            "old_digest": old_digest, "new_digest": digest, "size": actual_asset.get("size"),
            "old_process": installer.process_identity(), "arguments": list(sys.argv[1:]),
        }
        installer.write_json(stage / "plan.json", plan)
        installer.load_plan(stage / "plan.json", token)
        update_progress.set_phase(run_id, "starting_installer")
        process = installer.launch_executable(stage / "helper.exe", [
            "--apply-update", str(stage / "plan.json"), token,
        ])
        _wait_ready(stage, process)
        update_progress.set_phase(run_id, "restarting")
        before_restart()
    except BaseException:
        try:
            if downloaded is not None and stage is not None and downloaded.parent == stage:
                with suppress(OSError):
                    downloaded.unlink(missing_ok=True)
            if stage is not None:
                _cancel_and_clean(stage, token, process)
        finally:
            if run_id is not None:
                update_progress.fail(run_id)
        raise
    finally:
        _prepare_lock.release()
