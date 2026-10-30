"""Isolated, bounded transport checks. No Telegram account or route changes."""
from __future__ import annotations

import asyncio
import contextvars
import errno
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import platform
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Mapping
from urllib.parse import urlencode

from proxy import __version__
from proxy.config import CFPROXY_DEFAULT_DOMAINS, coerce_domain_list, parse_dc_ip_list
from proxy.helper_conn import HelperConnection, normalize_fingerprint
from proxy.raw_websocket import RawWebSocket, WsHandshakeError
from proxy.utils import DC_DEFAULT_IPS, DC_TEST_IPS, WS_PATH, WS_PATH_TEST, ws_domains
from utils.helper_config import effective_helper_mode

log = logging.getLogger("tg-diagnostics")
MAX_PARALLEL = 4
ATTEMPT_TIMEOUT = 8.0
RUN_TIMEOUT = 60.0
CLEANUP_TIMEOUT = 1.0
MAX_CANDIDATES = 3
_IDENTITY_KEY = os.urandom(32)
_OWNED_TRANSPORTS = contextvars.ContextVar("diagnostic_transports", default=None)
_DNS_SLOTS = threading.BoundedSemaphore(MAX_PARALLEL)
_DCS = (1, 2, 3, 4, 5, 203)
_KINDS = frozenset(("local", "direct", "fronted", "helper", "cf", "worker", "h2", "tcp"))
_STATUSES = frozenset(("ok", "error", "skipped", "cancelled", "incomplete"))
_ERRORS = frozenset(("", "proxy_stopped", "invalid_config", "dns", "timeout", "refused",
    "unreachable", "tls", "helper_rejected", "http_forbidden", "http_rate_limited",
    "http_server_error", "http_redirect", "ws_upgrade", "http_error", "connection",
    "not_configured", "disabled", "legacy_unconfirmed", "h2_unconfirmed", "tcp_unconfirmed",
    "insecure_skipped", "not_applicable", "cancelled", "deadline"))
_NETWORK_KEYS = ("host", "port", "secret", "dc_ip", "pool_size", "cfproxy", "h2",
    "cfproxy_user_domain_enabled", "cfproxy_user_domain", "cfproxy_worker_enabled",
    "cfproxy_worker_domain", "force_test_dc", "no_secure", "helper_enabled", "helper_mode",
    "helper_host", "helper_port", "helper_fingerprint", "helper_token_dpapi", "helper_registry", "proxy_protocol")


@dataclass(frozen=True)
class DiagnosticsSnapshot:
    identity: str
    running: bool
    host: str = field(repr=False)
    port: int = field(repr=False)
    redirects: tuple[tuple[int, str], ...] = field(repr=False)
    cf_domains: tuple[str, ...] = field(repr=False)
    workers: tuple[str, ...] = field(repr=False)
    use_cf: bool = field(repr=False)
    h2: bool = field(repr=False)
    insecure: bool = field(repr=False)
    test_dc: bool = field(repr=False)
    pool_size: int = field(repr=False)
    helper_mode: str = field(repr=False)
    helper_host: str = field(repr=False)
    helper_port: int = field(repr=False)
    helper_fingerprint: str = field(repr=False)
    helper_token: str = field(repr=False)
    helper_registry: bool = field(default=False, repr=False)
    invalid: bool = field(default=False, repr=False)


@dataclass(frozen=True)
class ProbeResult:
    kind: str
    label: str
    dc: int | None = None
    media: bool | None = None
    status: str = "skipped"
    error_code: str = "not_configured"
    setup_ms: float | None = None
    candidate_index: int = 0


@dataclass(frozen=True)
class Coverage:
    kind: str
    tested: int
    total: int


@dataclass(frozen=True)
class DiagnosticsReport:
    results: tuple[ProbeResult, ...]
    status: str
    recommendation: str
    started_at: str
    version: str
    duration_ms: float
    coverage: tuple[Coverage, ...] = ()
    identity: str = field(default="", repr=False)
    running: bool = False
    platform: str = ""
    architecture: str = ""


def _integer(value, default):
    try:
        return int(value)
    except (ValueError, TypeError, OverflowError):
        return default


def _identity_value(value):
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_identity_value(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _identity_value(v) for k, v in value.items()}
    return type(value).__name__


def make_snapshot(config: Mapping, *, running: bool, generation=None, active=None) -> DiagnosticsSnapshot:
    """Copy the supplied config only; never apply it or read a profile file."""
    cfg = dict(config)
    invalid = False
    try:
        redirects = parse_dc_ip_list(cfg.get("dc_ip", ["2:149.154.167.220", "4:149.154.167.220"]))
    except (ValueError, TypeError):
        redirects, invalid = {}, True
    user_domains = coerce_domain_list(cfg.get("cfproxy_user_domain", []))
    workers = coerce_domain_list(cfg.get("cfproxy_worker_domain", []))
    user_domains = user_domains if cfg.get("cfproxy_user_domain_enabled", bool(user_domains)) else []
    workers = workers if cfg.get("cfproxy_worker_enabled", bool(workers)) else []
    mode = effective_helper_mode(cfg)
    token = ""
    if active is None and mode == "tls-pin" and cfg.get("helper_registry") is not True and cfg.get("helper_token_dpapi"):
        try:
            from utils.secure_storage import unprotect_token
            token = unprotect_token(cfg["helper_token_dpapi"])
        except Exception:
            # A closed validation code is returned by the Helper check below.
            token = ""
    values = {
        "host": str(cfg.get("host", "127.0.0.1")), "port": _integer(cfg.get("port", 1443), 0),
        "redirects": redirects, "cf_domains": user_domains or list(CFPROXY_DEFAULT_DOMAINS),
        "workers": workers, "use_cf": cfg.get("cfproxy", True) is True,
        "h2": cfg.get("h2", True) is True, "insecure": cfg.get("no_secure", False) is True,
        "test_dc": cfg.get("force_test_dc", False) is True,
        "pool_size": _integer(cfg.get("pool_size", 4), 0), "helper_mode": mode,
        "helper_host": str(cfg.get("helper_host", "")).strip(),
        "helper_port": _integer(cfg.get("helper_port", 8444), 0),
        "helper_fingerprint": str(cfg.get("helper_fingerprint", "")), "helper_token": token,
        "helper_registry": cfg.get("helper_registry") is True,
    }
    if active is not None:
        names = {"redirects": "dc_redirects", "cf_domains": "cfproxy_user_domains",
            "workers": "cfproxy_worker_domains", "use_cf": "fallback_cfproxy",
            "h2": "cfproxy_h2_media", "insecure": "disable_secure", "test_dc": "force_test_dc"}
        for name in values:
            value = getattr(active, names.get(name, name), values[name])
            values[name] = value
        values["cf_domains"] = values["cf_domains"] or list(CFPROXY_DEFAULT_DOMAINS)
        invalid = False  # The running proxy already validated its active mapping.
    values["redirects"] = tuple(sorted(dict(values["redirects"]).items()))
    values["cf_domains"] = tuple(coerce_domain_list(values["cf_domains"]))
    values["workers"] = tuple(coerce_domain_list(values["workers"]))
    payload = {"saved": {k: _identity_value(cfg.get(k)) for k in _NETWORK_KEYS},
               "active": _identity_value(values), "running": bool(running),
               "generation": _identity_value(generation)}
    identity = hmac.new(_IDENTITY_KEY, json.dumps(payload, sort_keys=True, ensure_ascii=True,
        separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    return DiagnosticsSnapshot(identity=identity, running=bool(running), invalid=invalid, **values)


def _label(kind, dc=None, media=None, candidate_index=0):
    name = {"local": "Local proxy TCP", "direct": "Telegram WebSocket",
        "fronted": "Telegram fronted WebSocket", "helper": "Helper TLS route",
        "cf": "Cloudflare WebSocket", "worker": "Configured Worker",
        "h2": "HTTP/2 media", "tcp": "Telegram TCP fallback"}.get(kind, "Unknown check")
    if kind in ("cf", "worker") and candidate_index in (1, 2, 3):
        name += f" #{candidate_index}"
    if dc in _DCS:
        name += f" DC{dc}"
    if media is not None:
        name += " media endpoint" if media else " message endpoint"
    return name


@dataclass(frozen=True)
class _Probe:
    kind: str
    dc: int | None = None
    media: bool | None = None
    host: str = field(default="", repr=False)
    domain: str = field(default="", repr=False)
    path: str = field(default=WS_PATH, repr=False)
    port: int = field(default=443, repr=False)
    skip: str = ""
    candidate_index: int = 0


def _valid_host(host):
    if not isinstance(host, str) or not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return False
        return all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p)
                   for p in host.rstrip(".").split("."))


def _build_probes(s):
    local_host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(s.host, s.host)
    probes = [_Probe("local", host=local_host, port=s.port,
                     skip="proxy_stopped" if not s.running else "")]
    redirects = dict(s.redirects)
    dcs = tuple(DC_TEST_IPS) if s.test_dc else _DCS
    path = WS_PATH_TEST if s.test_dc else WS_PATH
    cf_total = worker_total = 0
    for dc in dcs:
        for media in (False, True):
            domains = ws_domains(dc, media)
            target = redirects.get(dc, "")
            skip = "invalid_config" if s.invalid else ("disabled" if s.pool_size <= 0 else
                                                        ("not_configured" if not target else ""))
            # The media-specific endpoint is reported distinctly from its normal fallback.
            for kind in ("direct", "fronted"):
                probes.append(_Probe(kind, dc, media, target, domains[0], path, skip=skip))
            helper_skip = ("not_applicable" if s.test_dc else
                           "not_configured" if s.helper_mode == "direct" else
                           "legacy_unconfirmed" if s.helper_mode == "legacy" else
                           "")
            probes.append(_Probe("helper", dc, media, s.helper_host, domains[0], skip=helper_skip))
        cf_total += len(s.cf_domains) if s.use_cf and not s.test_dc else 0
        worker_total += len(s.workers)
        cf_skip = "not_applicable" if s.test_dc else ("disabled" if not s.use_cf else
                                                    "insecure_skipped" if s.insecure else "")
        worker_skip = "insecure_skipped" if s.insecure else ""
        if cf_skip or not s.cf_domains:
            probes.append(_Probe("cf", dc, skip=cf_skip or "not_configured"))
        else:
            for candidate_index, base in enumerate(s.cf_domains[:MAX_CANDIDATES], 1):
                domain = f"kws{dc}.{base}"
                probes.append(_Probe("cf", dc, host=domain, domain=domain, candidate_index=candidate_index))
        if worker_skip or not s.workers:
            probes.append(_Probe("worker", dc, skip=worker_skip or "not_configured"))
        else:
            for candidate_index, domain in enumerate(s.workers[:MAX_CANDIDATES], 1):
                destinations = DC_TEST_IPS if s.test_dc else DC_DEFAULT_IPS
                query = urlencode({"dst": destinations[dc], "dc": str(dc)})
                probes.append(_Probe("worker", dc, host=domain, domain=domain, path=f"/apiws?{query}",
                                     candidate_index=candidate_index))
    probes.extend((_Probe("h2", skip="h2_unconfirmed" if s.h2 and s.use_cf and
                         not s.insecure and not s.test_dc else "disabled"),
                   _Probe("tcp", skip="tcp_unconfirmed")))
    # Round-robin route families so slow CF cannot starve Helper/direct checks.
    head, remaining = probes[:1], probes[1:]
    buckets = [[p for p in remaining if p.kind == kind] for kind in
               ("direct", "helper", "cf", "worker", "fronted", "h2", "tcp")]
    ordered = head
    while any(buckets):
        for bucket in buckets:
            if bucket:
                ordered.append(bucket.pop(0))
    return ordered, {"cf": cf_total, "worker": worker_total}


class _DaemonResolver:
    """A stuck OS DNS resolver cannot hold up cancellation/process shutdown."""
    def __init__(self, loop):
        self.loop = loop
        self.slots = _DNS_SLOTS

    async def getaddrinfo(self, host, port, *, family=0, type=0, proto=0, flags=0):
        while not self.slots.acquire(blocking=False):
            await asyncio.sleep(.025)
        future = self.loop.create_future()

        def deliver(value, error):
            if not future.done():
                if error is not None:
                    future.set_exception(error)
                else:
                    future.set_result(value)

        def resolve():
            value, error = None, None
            try:
                value = socket.getaddrinfo(host, port, family=family, type=type, proto=proto, flags=flags)
            except Exception as exc:
                error = exc
            finally:
                self.slots.release()
            try:
                self.loop.call_soon_threadsafe(deliver, value, error)
            except RuntimeError:
                pass  # The private loop has already closed after cancellation.

        try:
            threading.Thread(target=resolve, name="diagnostics-dns", daemon=True).start()
        except BaseException:
            self.slots.release()
            future.cancel()
            raise
        return await future


def _error_code(exc):
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, PermissionError):
        return "helper_rejected"
    if isinstance(exc, WsHandshakeError):
        code = exc.status_code
        return ("http_forbidden" if code == 403 else "http_rate_limited" if code == 429 else
                "http_server_error" if 500 <= code <= 599 else "http_redirect" if exc.is_redirect else
                "ws_upgrade" if code in (0, 101) else "http_error")
    if isinstance(exc, ValueError):
        return "invalid_config"
    if isinstance(exc, ConnectionRefusedError) or getattr(exc, "winerror", None) == 10061:
        return "refused"
    if getattr(exc, "errno", None) in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        return "unreachable"
    return "connection"


async def _close_connection(connection):
    writer = getattr(connection, "writer", connection)
    try:
        async with asyncio.timeout(CLEANUP_TIMEOUT):
            if hasattr(connection, "close") and connection is not writer:
                await connection.close()
            else:
                writer.close()
                await writer.wait_closed()
    except (Exception, asyncio.CancelledError):
        try:
            writer.close()
        except Exception:
            pass
        try:
            writer.transport.abort()
        except Exception:
            pass


async def _connect(probe, snapshot):
    if not _valid_host(probe.host) or not 1 <= probe.port <= 65535:
        raise ValueError("invalid_config")
    if probe.kind == "local":
        _, writer = await asyncio.open_connection(probe.host, probe.port)
        return writer
    if probe.kind == "helper":
        if snapshot.helper_registry:
            from utils.helper_registry import discover_helper
            cancelled = threading.Event()
            try:
                lease = await asyncio.to_thread(discover_helper, snapshot.helper_host,
                                               cancel_event=cancelled)
                return await HelperConnection.connect_v2(lease.host, lease.port,
                    lease.fingerprint, lease.token, probe.domain)
            finally:
                cancelled.set()
        if (not 1 <= snapshot.helper_port <= 65535 or not snapshot.helper_token or
                not 1 <= len(snapshot.helper_token.encode("utf-8")) <= 512 or
                len(normalize_fingerprint(snapshot.helper_fingerprint)) != 64):
            raise ValueError("invalid_config")
        return await HelperConnection.connect_v2(snapshot.helper_host, snapshot.helper_port,
            snapshot.helper_fingerprint, snapshot.helper_token, probe.domain)
    if not _valid_host(probe.domain):
        raise ValueError("invalid_config")
    return await RawWebSocket.connect(probe.host, probe.domain, timeout=ATTEMPT_TIMEOUT,
        path=probe.path, sni="sprinthost.ru" if probe.kind == "fronted" else None, secure=True)


async def _attempt(probe, snapshot, *, connector=None):
    """Bound cancellation cleanup even if a protocol's TLS close is waiting."""
    transports = []
    token = _OWNED_TRANSPORTS.set(transports)
    task = asyncio.create_task((connector or _connect)(probe, snapshot))
    succeeded = False
    try:
        done, _ = await asyncio.wait((task,), timeout=ATTEMPT_TIMEOUT)
        if not done:
            raise TimeoutError()
        result = task.result()
        succeeded = True
        return result
    finally:
        if not succeeded:
            for transport in transports:
                transport.abort()
            if not task.done():
                task.cancel()
                done, _ = await asyncio.wait((task,), timeout=CLEANUP_TIMEOUT)
                if not done:
                    task.cancel()  # Interrupt protocol-level cancellation cleanup.
                    await asyncio.wait((task,), timeout=CLEANUP_TIMEOUT)
            if task.done() and not task.cancelled():
                # Retrieve safe ownership if completion raced the deadline.
                try:
                    connection = task.result()
                except BaseException:
                    pass
                else:
                    await _close_connection(connection)
        _OWNED_TRANSPORTS.reset(token)


async def _run(snapshot, cancel, emit, started_at, start):
    probes, totals = _build_probes(snapshot)
    results = [None] * len(probes)
    semaphore = asyncio.Semaphore(MAX_PARALLEL)
    completed = 0

    def publish(index, status, code="", elapsed=None):
        nonlocal completed
        if results[index] is not None:
            return
        p = probes[index]
        result = ProbeResult(p.kind, _label(p.kind, p.dc, p.media, p.candidate_index), p.dc, p.media,
                             status, code, elapsed, p.candidate_index)
        results[index] = result
        completed += 1
        if status == "error":
            log.warning("Check %s: %s", result.label, code)
        elif status in ("ok", "incomplete", "cancelled"):
            log.info("Check %s: %s", result.label, status)
        try:
            emit({"kind": "progress", "result": result, "completed": completed, "total": len(probes)})
        except Exception:
            pass  # A closed UI must not keep networking alive or leak exceptions.

    async def check(index, probe):
        if probe.skip:
            publish(index, "error" if probe.skip in ("proxy_stopped", "invalid_config") else "skipped", probe.skip)
            return
        connection = None
        status, code, elapsed = "cancelled", "cancelled", None
        async with semaphore:
            if cancel.is_set():
                publish(index, status, code)
                return
            begin = time.monotonic()
            try:
                connection = await _attempt(probe, snapshot)
                elapsed = (time.monotonic() - begin) * 1000
                status, code = "ok", ""
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                status, code = "error", _error_code(exc)
            finally:
                if connection is not None:
                    await _close_connection(connection)
            publish(index, status, code, elapsed)

    tasks = [asyncio.create_task(check(i, p)) for i, p in enumerate(probes)]
    run_status = "complete"
    deadline = time.monotonic() + RUN_TIMEOUT
    while any(not task.done() for task in tasks):
        if cancel.is_set() or time.monotonic() >= deadline:
            run_status = "cancelled" if cancel.is_set() else "partial"
            for task in tasks:
                if not task.done():
                    task.cancel()
            break
        await asyncio.sleep(.025)
    # All protocol classes close their writer on failed/cancelled handshake.
    # Successful connections are owned here and have bounded close/abort.
    await asyncio.gather(*tasks, return_exceptions=True)
    if cancel.is_set():
        run_status = "cancelled"
    for index, result in enumerate(results):
        if result is None:
            publish(index, "cancelled" if run_status == "cancelled" else "incomplete",
                    "cancelled" if run_status == "cancelled" else "deadline")
    values = tuple(results)
    coverage = []
    for kind in ("local", "direct", "fronted", "helper", "cf", "worker", "h2", "tcp"):
        attempted = sum(r.kind == kind and r.status in ("ok", "error") and
                        r.error_code not in ("proxy_stopped", "invalid_config") for r in values)
        total = totals.get(kind, sum(p.kind == kind and not p.skip for p in probes))
        coverage.append(Coverage(kind, attempted, total))
        if attempted < total:
            run_status = "partial" if run_status == "complete" else run_status
    if run_status == "cancelled":
        recommendation = "retry"
    elif not snapshot.running:
        recommendation = "start_proxy"
    elif any(r.kind == "local" and r.status == "error" for r in values):
        recommendation = "open_routes"
    elif any(r.kind in ("direct", "fronted", "helper", "cf", "worker") and r.status == "ok" for r in values):
        recommendation = "open_telegram"
    else:
        recommendation = "open_routes"
    log.info("Connection check finished: %s; completed=%d/%d", run_status, completed, len(probes))
    return DiagnosticsReport(values, run_status, recommendation, started_at, __version__,
        (time.monotonic() - start) * 1000, tuple(coverage), snapshot.identity, snapshot.running,
        _safe_text(platform.system()) + " " + _safe_text(platform.release()), _safe_text(platform.machine()))


def create_probe_loop():
    """Private transport ownership and bounded daemon DNS, shared by UI probes."""
    loop = asyncio.new_event_loop()
    loop.getaddrinfo = _DaemonResolver(loop).getaddrinfo
    create_connection = loop.create_connection

    async def owned_connection(*args, **kwargs):
        transport, protocol = await create_connection(*args, **kwargs)
        owned = _OWNED_TRANSPORTS.get()
        if owned is not None:
            owned.append(transport)
        return transport, protocol

    loop.create_connection = owned_connection
    return loop


def run_diagnostics(snapshot: DiagnosticsSnapshot, cancel: threading.Event, emit: Callable) -> DiagnosticsReport:
    """Own a private loop; no default executor shutdown can wait on stuck DNS."""
    start = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    log.info("Connection check started")
    loop = create_probe_loop()
    try:
        return loop.run_until_complete(_run(snapshot, cancel, emit, started_at, start))
    finally:
        loop.close()


def _safe_text(value):
    return re.sub(r"[^A-Za-z0-9 ._+-]", "", str(value))[:80]


def _milliseconds(value):
    return f"{value:.0f}" if isinstance(value, (float, int)) and math.isfinite(value) and 0 <= value < 1e9 else "n/a"


def format_report(report: DiagnosticsReport) -> str:
    """Explicit allowlist; never serialize a snapshot, arbitrary label or exception."""
    version = report.version if re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", report.version) else "unknown"
    when = report.started_at if re.fullmatch(r"[0-9TZ:.+\-]{1,40}", report.started_at) else "unknown"
    status = report.status if report.status in ("complete", "partial", "cancelled") else "partial"
    recommendation = report.recommendation if report.recommendation in (
        "start_proxy", "open_routes", "open_telegram", "retry") else "retry"
    lines = [f"TG Proxy connection diagnostics {version}", f"UTC: {when}",
        f"System: {_safe_text(report.platform)}; architecture={_safe_text(report.architecture)}",
        f"Status: {status}; proxy_running={report.running is True}; duration_ms={_milliseconds(report.duration_ms)}",
        f"Recommendation: {recommendation}",
        "Scope: transport availability only. Telegram delivery and media downloads are not verified.",
        "No account access. No settings or routing changes."]
    for result in report.results:
        kind = result.kind if result.kind in _KINDS else "unknown"
        state = result.status if result.status in _STATUSES else "incomplete"
        code = result.error_code if result.error_code in _ERRORS else "connection"
        lines.append(f"{_label(kind, result.dc, result.media, result.candidate_index)}: {state}; code={code or 'none'}; setup_ms={_milliseconds(result.setup_ms)}")
    for coverage in report.coverage:
        if coverage.kind in _KINDS:
            tested, total = coverage.tested, coverage.total
            if isinstance(tested, int) and isinstance(total, int) and 0 <= tested <= total <= 1000000:
                lines.append(f"Coverage {coverage.kind}: {tested}/{total}")
    return "\n".join(lines)
