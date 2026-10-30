"""Bounded settings checks using the production TLS/WebSocket handshake.

No working pools, configuration mutation, raw responses or remote identifiers
are retained in results. A failed TLS attempt never retries as plaintext.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field

from proxy.raw_websocket import RawWebSocket
from utils.connection_diagnostics import (
    MAX_PARALLEL, ATTEMPT_TIMEOUT, RUN_TIMEOUT, _attempt, _close_connection,
    _error_code, _valid_host, create_probe_loop,
)

log = logging.getLogger('tg-diagnostics')
MAX_DOMAINS = 3
MAX_CASES = MAX_DOMAINS * 6
_RUN_LOCK = threading.Lock()


@dataclass(frozen=True)
class RouteCase:
    candidate: int
    dc: int
    host: str = field(repr=False)
    sni: str = field(repr=False)
    domain: str = field(repr=False)
    path: str = field(repr=False)


@dataclass(frozen=True)
class RouteResult:
    candidate: int
    dc: int
    status: str
    error_code: str = ''


async def _connect_case(case, secure):
    if (not all(_valid_host(h) for h in (case.host, case.sni, case.domain))
            or not isinstance(case.path, str) or not case.path.startswith('/')
            or len(case.path) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in case.path)):
        raise ValueError('invalid_config')
    return await RawWebSocket.connect(case.host, case.domain,
        timeout=ATTEMPT_TIMEOUT, path=case.path,
        sni=case.sni if case.sni != case.domain else None, secure=secure)


async def _run(cases, secure, cancel):
    results = [None] * len(cases)
    semaphore = asyncio.Semaphore(MAX_PARALLEL)

    async def check(index, case):
        connection = None
        async with semaphore:
            if cancel.is_set():
                return
            try:
                connection = await _attempt(case, secure, connector=_connect_case)
                results[index] = RouteResult(case.candidate, case.dc, 'ok')
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                results[index] = RouteResult(case.candidate, case.dc, 'error', _error_code(exc))
            finally:
                if connection is not None:
                    await _close_connection(connection)

    tasks = [asyncio.create_task(check(i, case)) for i, case in enumerate(cases)]
    deadline = time.monotonic() + RUN_TIMEOUT
    while any(not task.done() for task in tasks):
        if cancel.is_set() or time.monotonic() >= deadline:
            for task in tasks:
                if not task.done():
                    task.cancel()
            break
        await asyncio.sleep(.025)
    await asyncio.gather(*tasks, return_exceptions=True)
    for i, case in enumerate(cases):
        if results[i] is None:
            status = 'cancelled' if cancel.is_set() else 'incomplete'
            results[i] = RouteResult(case.candidate, case.dc, status,
                                     'cancelled' if cancel.is_set() else 'deadline')
    return tuple(results)


def run_route_checks(cases, *, secure=True, cancel=None):
    """Run at most 18 checks, 4 concurrently, with 8/60 second deadlines."""
    cases = tuple(cases)
    if len(cases) > MAX_CASES:
        raise ValueError('route_limit')
    cancel = cancel if cancel is not None else threading.Event()
    if not _RUN_LOCK.acquire(blocking=False):
        return tuple(RouteResult(c.candidate, c.dc, 'incomplete', 'busy') for c in cases)
    loop = None
    log.info('Settings route check started: cases=%d; tls=%s', len(cases), bool(secure))
    try:
        loop = create_probe_loop()
        values = loop.run_until_complete(_run(cases, bool(secure), cancel))
        log.info('Settings route check finished: ok=%d; total=%d; cancelled=%s',
                 sum(v.status == 'ok' for v in values), len(values), cancel.is_set())
        return values
    finally:
        if loop is not None:
            loop.close()
        _RUN_LOCK.release()
