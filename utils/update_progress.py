"""Process-local update progress snapshots, containing no release credentials."""
from __future__ import annotations

import re
import threading

_lock = threading.Lock()
_run_id = 0
_PHASES = frozenset(("preparing", "downloading", "verifying", "starting_installer", "restarting"))
_VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
                      r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
                      r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z")
_state = {"active": False, "phase": "idle", "downloaded": 0, "total": None, "version": ""}


def _version(value):
    return value if isinstance(value, str) and len(value) <= 128 and _VERSION.fullmatch(value) else ""


def _total(value):
    return value if type(value) is int and value > 0 else None


def begin(version: str = "") -> int:
    """Start a generation. The installer holds its busy lock before calling."""
    global _run_id
    with _lock:
        _run_id += 1
        _state.update(active=True, phase="preparing", downloaded=0, total=None, version=_version(version))
        return _run_id


def start_download(run_id: int, version: str, total: int | None = None) -> bool:
    """Reset counts and identity for an actual candidate, including fallback."""
    with _lock:
        if run_id != _run_id or not _state["active"]:
            return False
        _state.update(phase="downloading", downloaded=0, total=_total(total), version=_version(version))
        return True


def set_download(run_id: int, downloaded: int, total: int | None) -> bool:
    with _lock:
        if run_id != _run_id or not _state["active"] or _state["phase"] != "downloading":
            return False
        if type(downloaded) is not int or downloaded < 0:
            return False
        _state.update(downloaded=downloaded, total=_total(total))
        return True


def set_phase(run_id: int, phase: str) -> bool:
    if phase not in _PHASES:
        raise ValueError("Unknown active update phase")
    with _lock:
        if run_id != _run_id or not _state["active"]:
            return False
        _state["phase"] = phase
        return True


def fail(run_id: int) -> bool:
    with _lock:
        if run_id != _run_id or not _state["active"]:
            return False
        _state.update(active=False, phase="failed")
        return True


def clear_finished() -> bool:
    """UI dismissal cannot erase a download/install currently in progress."""
    with _lock:
        if _state["active"]:
            return False
        _state.update(active=False, phase="idle", downloaded=0, total=None, version="")
        return True


def get_progress() -> dict:
    with _lock:
        return dict(_state)
