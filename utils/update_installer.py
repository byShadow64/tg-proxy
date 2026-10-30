"""Private Windows updater protocol; imported before the application bootstrap.

The copied executable runs this module without opening the application, touching
its settings, or taking its single-instance lock. All filesystem mutations are
limited to one validated executable and an allowlist in its adjacent workspace.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path

STAGING_PREFIX = ".tgproxy-update-"
LOCK_NAME = ".tgproxy-update.lock"
_FILES = frozenset({"plan.json", "state.json", "ack.json", "cancel",
                    "helper.exe", "payload.exe", "previous.exe",
                    "plan.json.tmp", "state.json.tmp", "ack.json.tmp"})
_SHA256 = re.compile(r"(?:sha256:)?([0-9a-f]{64})", re.IGNORECASE)
_STAGING = re.compile(r"\.tgproxy-update-[0-9a-f]{32}")
_pending_ack = None


class UpdateBusyError(OSError):
    """Another installer owns this executable directory."""


def process_identity(pid=None):
    import psutil
    process = psutil.Process(os.getpid() if pid is None else pid)
    return {"pid": process.pid, "created": process.create_time()}


def process_alive(identity):
    import psutil
    try:
        return abs(psutil.Process(identity["pid"]).create_time() - identity["created"]) < .001
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied:
        return True


def _ordinary(path, *, required=False):
    try:
        stat = path.lstat()
    except FileNotFoundError:
        if required:
            raise ValueError("Missing update file") from None
        return
    if path.is_symlink() or getattr(stat, "st_file_attributes", 0) & 0x400:
        raise ValueError("Update paths cannot be links")


def file_digest(path):
    _ordinary(path, required=True)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_payload(path, digest, size=None):
    expected = _SHA256.fullmatch(digest if isinstance(digest, str) else "")
    if not expected:
        raise ValueError("The release asset has no valid SHA-256 checksum")
    if size is not None and (type(size) is not int or size <= 0 or path.stat().st_size != size):
        raise ValueError("The release asset size does not match")
    if file_digest(path) != expected[1].lower():
        raise ValueError("The release asset checksum does not match")
    return expected[1].lower()


def _read_json(path):
    _ordinary(path, required=True)
    if path.stat().st_size > 65536:
        raise ValueError("Oversized update record")
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError("Invalid update record")
    return value


def write_json(path, value):
    _ordinary(path)
    temporary = path.with_name(path.name + ".tmp")
    _ordinary(temporary)
    with temporary.open("w", encoding="utf-8") as target:
        json.dump(value, target, ensure_ascii=True)
        target.flush()
        os.fsync(target.fileno())
    deadline = time.monotonic() + 2
    while True:
        _ordinary(path)
        _ordinary(temporary)
        try:
            os.replace(temporary, path)
            return
        except OSError as error:
            # A brief status/ACK reader can block replacement on Windows.
            # Keep the atomic write and path checks while that handle closes.
            if sys.platform != "win32" or getattr(error, "winerror", None) not in (5, 32, 33):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(.02, remaining))


def load_plan(path, token):
    path = Path(path).absolute()
    stage = path.parent
    if path.name != "plan.json" or not _STAGING.fullmatch(stage.name):
        raise ValueError("Invalid update workspace")
    _ordinary(stage, required=True)
    if stage.resolve() != stage:
        raise ValueError("Update workspace cannot be redirected")
    plan = _read_json(path)
    if plan.get("schema") != 1 or not re.fullmatch(r"[0-9a-f]{64}", str(token)):
        raise ValueError("Invalid update protocol")
    if plan.get("token") != token:
        raise ValueError("Invalid update token")
    name = plan.get("target")
    if (not isinstance(name, str) or not name.lower().endswith(".exe") or
            any(character in name for character in "\\/:\0") or
            name.rstrip(" .") != name or Path(name).name != name):
        raise ValueError("Invalid executable name")
    for key in ("old_digest", "new_digest"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(plan.get(key))):
            raise ValueError("Invalid update checksum")
    old = plan.get("old_process", {})
    if type(old.get("pid")) is not int or old["pid"] <= 0 or not isinstance(old.get("created"), (int, float)):
        raise ValueError("Invalid update process")
    arguments = plan.get("arguments")
    if (not isinstance(arguments, list) or len(arguments) > 128 or
            any(not isinstance(arg, str) or len(arg) > 32768 or "\0" in arg for arg in arguments) or
            any(arg.startswith(("--apply-update", "--cleanup-update", "--update-ack")) for arg in arguments)):
        raise ValueError("Invalid update arguments")
    if abs(time.time() - plan.get("created", 0)) > 3600:
        raise ValueError("Expired update plan")
    target = stage.parent / name
    _ordinary(target, required=True)
    for name in _FILES:
        _ordinary(stage / name)
    plan["_stage"], plan["_target"] = stage, target
    return plan


def acquire_install_lock(directory, token, stage):
    path = directory / LOCK_NAME
    _ordinary(path)
    record = {"token": token, "stage": stage.name, "owner": process_identity()}
    for attempt in range(2):
        try:
            with path.open("x", encoding="utf-8") as target:
                json.dump(record, target)
            return
        except FileExistsError:
            existing = _read_json(path)
            if (attempt or not _STAGING.fullmatch(str(existing.get("stage", ""))) or
                    not re.fullmatch(r"[0-9a-f]{64}", str(existing.get("token", ""))) or
                    process_alive(existing.get("owner", {}))):
                raise UpdateBusyError("An update installation is already running") from None
            path.unlink()


def release_install_lock(plan):
    path = plan["_stage"].parent / LOCK_NAME
    with suppress(OSError, ValueError, KeyError, TypeError):
        if _read_json(path).get("token") == plan["token"]:
            path.unlink()


def _state(plan, stage, **extra):
    value = {"stage": stage, "helper": process_identity(), **extra}
    write_json(plan["_stage"] / "state.json", value)
    return value


def launch_executable(executable, arguments):
    # Importing this here keeps helper dispatch free of UI/config imports.
    from utils.update_check import relaunch_env
    bundle = getattr(sys, "_MEIPASS", None)
    kernel = ctypes.windll.kernel32 if sys.platform == "win32" else None
    if bundle and kernel:
        kernel.SetDllDirectoryW(None)
    try:
        return subprocess.Popen(
            [str(executable), *arguments], cwd=str(executable.parent), env=relaunch_env(),
            close_fds=True,
            creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) |
                          getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
    finally:
        if bundle and kernel:
            kernel.SetDllDirectoryW(ctypes.c_wchar_p(bundle))


def _replace(source, target, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.replace(source, target)
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.1)


def _install_payload(plan, timeout=10):
    """ReplaceFileW keeps the canonical name and preserves its Windows ACLs."""
    target, stage = plan["_target"], plan["_stage"]
    if sys.platform != "win32":
        _replace(target, stage / "previous.exe", timeout)
        _replace(stage / "payload.exe", target, timeout)
        return
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    replace = kernel.ReplaceFileW
    replace.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                        ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
    replace.restype = ctypes.c_int
    deadline = time.monotonic() + timeout
    while not replace(str(target), str(stage / "payload.exe"), str(stage / "previous.exe"), 0, None, None):
        error = ctypes.get_last_error()
        # A partial ReplaceFile failure can already have moved the old file to
        # its backup. Leave that backup to the rollback path immediately.
        if (stage / "previous.exe").exists() or time.monotonic() >= deadline:
            raise ctypes.WinError(error)
        time.sleep(.1)


def _wait_old(plan, timeout):
    deadline = time.monotonic() + timeout
    while process_alive(plan["old_process"]):
        if (plan["_stage"] / "cancel").exists():
            raise InterruptedError("Update cancelled before replacement")
        if time.monotonic() >= deadline:
            raise TimeoutError("The previous application did not exit")
        time.sleep(.1)
    if (plan["_stage"] / "cancel").exists():
        raise InterruptedError("Update cancelled before replacement")


def _valid_ack(plan, attempt, launched):
    import psutil
    try:
        ack = _read_json(plan["_stage"] / "ack.json")
        if ack.get("attempt") != attempt or ack.get("token") != plan["token"]:
            return False
        identity = ack.get("process", {})
        process = psutil.Process(identity["pid"])
        if not process_alive(identity) or Path(process.exe()).resolve() != plan["_target"]:
            return False
        return process.pid == launched.pid or any(parent.pid == launched.pid for parent in process.parents())
    except (OSError, ValueError, KeyError, TypeError, psutil.Error):
        return False


def _wait_ack(plan, attempt, launched, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _valid_ack(plan, attempt, launched):
            return True
        if launched.poll() is not None:
            return False
        time.sleep(.1)
    return False


def _stop_launched(launched, identity, target):
    """Stop only this launch and its still-owned bootloader descendants."""
    import psutil
    if not process_alive(identity):
        return
    try:
        parent = psutil.Process(identity["pid"])
        children = []
        for child in parent.children(recursive=True):
            with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                if Path(child.exe()).resolve() == target:
                    children.append(child)
        processes = list(reversed(children)) + [parent]
        for process in processes:
            with suppress(psutil.NoSuchProcess):
                process.terminate()
        _, alive = psutil.wait_procs(processes, timeout=5)
        for process in alive:
            with suppress(psutil.NoSuchProcess):
                process.kill()
        _, alive = psutil.wait_procs(alive, timeout=5)
        if alive:
            raise TimeoutError("The unsuccessful updated application did not exit")
    except psutil.NoSuchProcess:
        pass


def _start_target(plan, *, rollback=False, launch=launch_executable):
    attempt = uuid.uuid4().hex
    stage = "rollback_launching" if rollback else "launching"
    _state(plan, stage, attempt=attempt)
    process = launch(plan["_target"], [*plan["arguments"], "--update-ack",
                                      str(plan["_stage"] / "plan.json"), plan["token"]])
    identity = process_identity(process.pid)
    _state(plan, "rollback_launched" if rollback else "launched", attempt=attempt,
           launched=identity)
    return process, identity, attempt


def run_update(path, token, *, launch=launch_executable, old_timeout=60, health_timeout=90):
    plan = load_plan(path, token)
    stage, target = plan["_stage"], plan["_target"]
    previous = stage / "previous.exe"
    replaced = False
    launched, launched_identity = None, None
    result = 1
    try:
        if Path(sys.executable).resolve() != stage / "helper.exe":
            raise ValueError("Updater must run from its private copy")
        verify_payload(stage / "helper.exe", plan["old_digest"])
        verify_payload(stage / "payload.exe", plan["new_digest"], plan.get("size"))
        verify_payload(target, plan["old_digest"])
        lock = _read_json(stage.parent / LOCK_NAME)
        if lock.get("token") != token:
            raise UpdateBusyError("The installer no longer owns its lock")
        lock["owner"] = process_identity()
        write_json(stage.parent / LOCK_NAME, lock)
        _state(plan, "ready")
        _wait_old(plan, old_timeout)
        # Recheck after waiting: another file cannot be substituted meanwhile.
        verify_payload(target, plan["old_digest"])
        verify_payload(stage / "payload.exe", plan["new_digest"], plan.get("size"))
        _state(plan, "replacing")
        _install_payload(plan)
        replaced = True
        launched, launched_identity, attempt = _start_target(plan, launch=launch)
        if not _wait_ack(plan, attempt, launched, health_timeout):
            raise TimeoutError("The updated application did not acknowledge startup")
        _state(plan, "complete")
        result = 0
    except BaseException as exc:
        if replaced or previous.exists():
            try:
                if launched is not None:
                    _stop_launched(launched, launched_identity, target)
                _replace(previous, target)
                verify_payload(target, plan["old_digest"])
                old, _, attempt = _start_target(plan, rollback=True, launch=launch)
                if not _wait_ack(plan, attempt, old, health_timeout):
                    raise TimeoutError("The restored application did not acknowledge startup")
                _state(plan, "rolled_back", error=type(exc).__name__)
            except BaseException as rollback_error:
                _state(plan, "rollback_failed", error=type(rollback_error).__name__)
        else:
            _state(plan, "cancelled" if isinstance(exc, InterruptedError) else "failed",
                   error=type(exc).__name__)
    finally:
        release_install_lock(plan)
        # A third, short-lived invocation can delete the helper after it exits.
        # It bypasses the normal application and its single-instance lock.
        with suppress(OSError, ValueError):
            launch(target, ["--cleanup-update", str(stage / "plan.json"), token])
    return result


def cleanup_update(path, token, *, timeout=30):
    plan = load_plan(path, token)
    stage = plan["_stage"]
    state = _read_json(stage / "state.json")
    deadline = time.monotonic() + timeout
    while process_alive(state["helper"]):
        if time.monotonic() >= deadline:
            return False
        time.sleep(.1)
    if state.get("stage") == "rollback_failed":
        return False  # Preserve the only good old executable for recovery.
    if file_digest(plan["_target"]) not in (plan["old_digest"], plan["new_digest"]):
        return False
    release_install_lock(plan)
    while True:
        # No recursive deletion, no globs, no paths supplied by the plan.
        for name in _FILES:
            file = stage / name
            _ordinary(file)
            with suppress(OSError):
                file.unlink(missing_ok=True)
        try:
            stage.rmdir()
            return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(.1)


def acknowledge_update():
    """Called by the new application only after successful initialization."""
    global _pending_ack
    request, _pending_ack = _pending_ack, None
    if request is None:
        return False
    try:
        plan = load_plan(*request)
        if Path(sys.executable).resolve() != plan["_target"]:
            return False
        state = _read_json(plan["_stage"] / "state.json")
        rollback = state.get("stage", "").startswith("rollback_")
        if state.get("stage") not in ("launching", "launched", "rollback_launching", "rollback_launched"):
            return False
        verify_payload(plan["_target"], plan["old_digest"] if rollback else plan["new_digest"])
        write_json(plan["_stage"] / "ack.json", {
            "token": plan["token"], "attempt": state["attempt"], "process": process_identity(),
        })
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def bootstrap_dispatch(argv=None):
    """Return an exit code for helper modes, None for normal application startup."""
    global _pending_ack
    argv = sys.argv if argv is None else argv
    for mode in ("--apply-update", "--cleanup-update", "--update-ack"):
        if mode not in argv:
            continue
        index = argv.index(mode)
        if index != len(argv) - 3 or (mode != "--update-ack" and index != 1):
            return 2
        path, token = argv[index + 1:]
        try:
            load_plan(path, token)
            if mode == "--apply-update":
                return run_update(path, token)
            if mode == "--cleanup-update":
                return 0 if cleanup_update(path, token) else 1
            _pending_ack = (path, token)
            del argv[index:]
            return None
        except (OSError, ValueError, KeyError, TypeError):
            return 2
    return None
