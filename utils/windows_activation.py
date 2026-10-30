"""One-bit, session-local activation of an existing Windows tray instance.

The owner creates an auto-reset event before application initialization. A
second instance can only open and signal it; there are no commands or payloads.
No Windows calls run when importing this module.
"""
from __future__ import annotations

import ctypes
import logging
import math
import re
import threading
import time
from ctypes import wintypes
from typing import Callable

log = logging.getLogger("tg-ws-tray")
_EVENT_MODIFY_STATE = 0x0002
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xFFFFFFFF
_WAIT_MS = 100
_JOIN_TIMEOUT = 1.0
_NAME = re.compile(r"Local\\[A-Za-z0-9_.-]{1,180}\Z")


def _validate_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError("An activation event needs a session-local application name")
    return name


def _kernel32():
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateEventW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR)
    api.CreateEventW.restype = wintypes.HANDLE
    api.OpenEventW.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR)
    api.OpenEventW.restype = wintypes.HANDLE
    api.SetEvent.argtypes = (wintypes.HANDLE,)
    api.SetEvent.restype = wintypes.BOOL
    api.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.CloseHandle.argtypes = (wintypes.HANDLE,)
    api.CloseHandle.restype = wintypes.BOOL
    return api


class InstanceActivation:
    """Own an event and invoke a callback only after ``start`` enables it.

    ``close`` is bounded. The worker owns closing its handle once started, so
    a slow callback cannot cause another thread to close a handle being waited
    upon. A callback already dispatched may finish after close.
    """

    def __init__(self, name: str):
        self.name = _validate_name(name)
        self._api = _kernel32()
        # Default DACL, no inheritance, auto-reset, initially unsignalled.
        self._handle = self._api.CreateEventW(None, False, False, self.name)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._closed = False
        self._thread = None

    @classmethod
    def create(cls, name: str) -> "InstanceActivation":
        return cls(name)

    def start(self, callback: Callable[[], None]) -> None:
        if not callable(callback):
            raise TypeError("An activation callback must be callable")
        with self._lock:
            if self._closed:
                raise RuntimeError("The activation channel is closed")
            if self._thread is not None:
                return
            thread = threading.Thread(target=self._run, args=(callback,),
                                      daemon=True, name="instance-activation")
            self._thread = thread
            try:
                thread.start()
            except BaseException:
                self._thread = None
                raise

    def _close_handle(self) -> None:
        with self._lock:
            handle, self._handle = self._handle, None
        if handle:
            self._api.CloseHandle(handle)

    def _run(self, callback: Callable[[], None]) -> None:
        # Once the worker starts, only its finally block releases this handle.
        handle = self._handle
        try:
            while not self._stop.is_set():
                result = self._api.WaitForSingleObject(handle, _WAIT_MS)
                if result == _WAIT_TIMEOUT:
                    continue
                if result != _WAIT_OBJECT_0:
                    error = ctypes.get_last_error() if result == _WAIT_FAILED else 0
                    log.warning("Instance activation wait failed (code=%d)", error)
                    return
                with self._lock:
                    if self._closed or self._stop.is_set():
                        return
                try:
                    callback()
                except Exception as exc:
                    log.warning("Instance activation callback failed (%s)", type(exc).__name__)
        finally:
            self._close_handle()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            thread = self._thread
            if thread is not None and self._handle:
                # Wake WaitForSingleObject; the stop bit suppresses activation.
                self._api.SetEvent(self._handle)
        if thread is None:
            self._close_handle()
        elif thread is not threading.current_thread():
            thread.join(timeout=_JOIN_TIMEOUT)


def request_activation(name: str, timeout: float = 3.0) -> bool:
    """Signal an owner's event, retrying briefly while startup creates it.

    Only OpenEvent is used: a second instance never creates or owns the channel.
    Handles opened for signalling are always released, including SetEvent errors.
    """
    name = _validate_name(name)
    timeout = float(timeout)
    if not math.isfinite(timeout) or not 0 <= timeout <= 30:
        raise ValueError("Activation timeout must be between zero and 30 seconds")
    api = _kernel32()
    deadline = time.monotonic() + timeout
    while True:
        handle = api.OpenEventW(_EVENT_MODIFY_STATE, False, name)
        if handle:
            try:
                if api.SetEvent(handle):
                    return True
            finally:
                api.CloseHandle(handle)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(.05, remaining))
