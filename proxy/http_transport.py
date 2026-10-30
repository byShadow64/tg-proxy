"""Bound synchronous HTTP DNS/TCP setup without orphaning unbounded workers.

The operating-system resolver cannot be interrupted. Timed-out daemon lookups
retain one of four slots until they actually finish; no replacement is started.
TLS and response processing remain the caller's responsibility.
"""
from __future__ import annotations

import queue
import socket
import threading
import time
from contextlib import suppress
from http.client import HTTPResponse

_DNS_SLOTS = threading.BoundedSemaphore(4)


def response_with_deadline(deadline):
    """Interrupt status/header/body/chunk parsing at an absolute deadline."""
    class DeadlineResponse(HTTPResponse):
        def __init__(self, sock, *args, **kwargs):
            self._expired = threading.Event()
            self._deadline_timer = threading.Timer(
                max(0, deadline - time.monotonic()), self._abort, args=(sock,))
            self._deadline_timer.daemon = True
            super().__init__(sock, *args, **kwargs)
            self._deadline_timer.start()

        def _abort(self, sock):
            self._expired.set()
            # Buffered-file close can wait for its reader lock. Shutdown also
            # interrupts reads after HTTPConnection detached a closing socket.
            with suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)

        def _check_deadline(self):
            if self._expired.is_set() or time.monotonic() >= deadline:
                raise TimeoutError("HTTP response exceeded its time limit")

        def begin(self):
            try:
                return super().begin()
            finally:
                self._check_deadline()

        def read(self, *args, **kwargs):
            try:
                return super().read(*args, **kwargs)
            finally:
                self._check_deadline()

        def read1(self, *args, **kwargs):
            try:
                return super().read1(*args, **kwargs)
            finally:
                self._check_deadline()

        def _close_conn(self):
            self._deadline_timer.cancel()
            return super()._close_conn()

        def close(self):
            self._deadline_timer.cancel()
            return super().close()

    return DeadlineResponse


def _addresses(address, deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError("HTTP connection deadline exceeded")
    slots = _DNS_SLOTS
    if not slots.acquire(blocking=False):
        raise TimeoutError("HTTP resolver capacity is busy")
    result = queue.Queue(maxsize=1)

    def resolve():
        try:
            value = socket.getaddrinfo(*address, 0, socket.SOCK_STREAM)
            result.put((True, tuple(value[:32])))
        except BaseException as error:
            result.put((False, error))
        finally:
            slots.release()

    try:
        threading.Thread(target=resolve, name="tg-http-dns", daemon=True).start()
    except Exception:
        slots.release()
        raise OSError("HTTP resolver could not start") from None
    except BaseException:
        slots.release()
        raise
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("HTTP DNS deadline exceeded")
    try:
        ok, value = result.get(timeout=remaining)
    except queue.Empty:
        raise TimeoutError("HTTP DNS deadline exceeded") from None
    if not ok:
        if isinstance(value, Exception):
            raise value
        raise OSError("HTTP DNS lookup failed") from None
    return value


def create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None, *, deadline):
    """socket.create_connection compatible subset with one DNS/TCP deadline."""
    if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT and timeout is not None:
        deadline = min(deadline, time.monotonic() + timeout)
    last_error = None
    for family, kind, protocol, _, sockaddr in _addresses(address, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP connection deadline exceeded")
        sock = None
        try:
            sock = socket.socket(family, kind, protocol)
            sock.settimeout(remaining)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP connection deadline exceeded")
            sock.settimeout(remaining)
            return sock
        except OSError as error:
            last_error = error
            if sock is not None:
                with suppress(OSError):
                    sock.close()
        except BaseException:
            if sock is not None:
                with suppress(OSError):
                    sock.close()
            raise
    if time.monotonic() >= deadline:
        raise TimeoutError("HTTP connection deadline exceeded")
    if last_error is not None:
        raise last_error
    raise OSError("HTTP address lookup returned no usable address")
