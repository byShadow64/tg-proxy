import logging
import os
import string
import random
import threading
import time

from dataclasses import dataclass, field
from typing import Dict, List
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request

from .balancer import balancer
from .utils import build_github_opener
from .route_policy import require_direct_route, require_relay_hostname
from .project import RAW_CONTENT_URL
from .http_transport import response_with_deadline

log = logging.getLogger('tg-mtproto-proxy')

CFPROXY_DOMAINS_URL = f"{RAW_CONTENT_URL}/.github/cfproxy-domains.txt"

_CFPROXY_ENC: List[str] = [
    'virkgj.com', 
    'vmmzovy.com', 
    'mkuosckvso.com', 
    'zaewayzmplad.com', 
    'twdmbzcm.com',
    'awzwsldi.com',
    'clngqrflngqin.com',
    'tjacxbqtj.com',
    'bxaxtxmrw.com',
    'dmohrsgmohcrwb.com',
    'vwbmtmoi.com',
    'khgrre.com',
    'ulihssf.com',
    'tmhqsdqmfpmk.com',
    'xwuwoqbm.com',
    'orgcnunpj.com',
    'zhkuldz.com',
    'zypoljnslxa.com',
    'efabnxaowuzs.com',
    'zaftuzsftqdq.com'
]
_S = ''.join(chr(c) for c in (46, 99, 111, 46, 117, 107))


def _dd(s: str) -> str:
    """Only for decoding CF proxy domains"""
    if not s[-4:] == '.com':
        return s
    p, n = s[:-4], sum(c.isalpha() for c in s[:-4])
    return ''.join(
        chr((ord(c) - (97 if c > '`' else 65) - n) % 26 + (97 if c > '`' else 65))
        if c.isalpha() else c for c in p
    ) + _S


CFPROXY_DEFAULT_DOMAINS: List[str] = [_dd(d) for d in _CFPROXY_ENC]
_CFPROXY_MIN_VALID_DOMAINS = 3
_CFPROXY_MAX_RESPONSE_BYTES = 64 * 1024
_CFPROXY_MAX_DOMAINS = 256
_refresh_fetch_lock = threading.Lock()
_refresh_state_lock = threading.RLock()


class _DomainListRedirect(HTTPRedirectHandler):
    handler_order = 100

    def http_error_302(self, req, fp, code, msg, headers):
        # urllib normally consumes an unbounded redirect body. This fetch
        # does not reuse the connection and only needs Location.
        fp.close()
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if target.scheme != 'https' or not target.hostname or target.username or target.password:
            raise ValueError("unsafe_domain_list_redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass
class ProxyConfig:
    port: int = 1443
    host: str = '127.0.0.1'
    secret: str = field(default_factory=lambda: os.urandom(16).hex())
    dc_redirects: Dict[int, str] = field(default_factory=lambda: {2: '149.154.167.220', 4: '149.154.167.220'})
    buffer_size: int = 256 * 1024
    pool_size: int = 4
    fallback_cfproxy: bool = True
    cfproxy_user_domains: List[str] = field(default_factory=list)
    cfproxy_worker_domains: List[str] = field(default_factory=list)
    cfproxy_h2_media: bool = True
    disable_secure: bool = False
    fake_tls_domain: str = ''
    proxy_protocol: bool = False
    force_test_dc: bool = False
    helper_mode: str = 'direct'
    helper_host: str = ''
    helper_port: int = 8444
    helper_fingerprint: str = ''
    helper_token: str = ''
    helper_registry: bool = False

    @property
    def h2_enabled(self) -> bool:
        return (self.cfproxy_h2_media and self.fallback_cfproxy
                and not self.disable_secure and not self.force_test_dc)


proxy_config = ProxyConfig()


def coerce_domain_list(value) -> List[str]:
    if isinstance(value, str):
        items = value.replace(',', ' ').replace(';', ' ').split()
    elif isinstance(value, (list, tuple)):
        items: List[str] = []
        for entry in value:
            if isinstance(entry, str):
                items.extend(entry.replace(',', ' ').replace(';', ' ').split())
    else:
        return []
    seen = set()
    result: List[str] = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _fetch_cfproxy_domain_list() -> List[str]:
    try:
        req = Request(CFPROXY_DOMAINS_URL + "?" + "".join(random.choices(string.ascii_letters, k=7)),
                       headers={'User-Agent': 'tg-ws-proxy'})
        deadline = time.monotonic() + 10
        opener = build_github_opener(response_class=response_with_deadline(deadline),
                                     connection_deadline=deadline)
        opener.add_handler(_DomainListRedirect())
        with opener.open(req, timeout=10) as resp:
            payload = resp.read(_CFPROXY_MAX_RESPONSE_BYTES + 1)
        if len(payload) > _CFPROXY_MAX_RESPONSE_BYTES:
            raise ValueError("domain_list_too_large")
        text = payload.decode('utf-8', errors='replace')
        encoded = [
            line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith('#')
        ]
        if len(encoded) > _CFPROXY_MAX_DOMAINS:
            raise ValueError("too_many_domains")
        return [_dd(d) for d in encoded]
    except Exception as exc:
        if isinstance(exc, HTTPError):
            exc.close()
        log.warning("Failed to fetch CF proxy domain list (%s)", type(exc).__name__)
        return []


def _is_valid_domain(domain: str) -> bool:
    try:
        require_relay_hostname(domain)
        return True
    except ValueError:
        return False


def _normalize_domain_pool(domains: List[str]) -> List[str]:
    seen = set()
    normalized: List[str] = []
    for domain in domains:
        item = domain.strip().lower()
        if not _is_valid_domain(item):
            continue
        if item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return normalized


def refresh_cfproxy_domains(stop: threading.Event | None = None) -> bool:
    if proxy_config.cfproxy_user_domains or (stop is not None and stop.is_set()):
        return True
    # A resolver/socket from an older generation may still be winding down.
    # Never multiply in-flight refreshes when the user restarts the proxy.
    if not _refresh_fetch_lock.acquire(blocking=False):
        return False
    try:
        fetched = _fetch_cfproxy_domain_list()
    finally:
        _refresh_fetch_lock.release()
    pool = _normalize_domain_pool(fetched)
    with _refresh_state_lock:
        # Fetching is outside the lock; a stopped generation or newly applied
        # manual route must never be overwritten by its late network response.
        if proxy_config.cfproxy_user_domains or (stop is not None and stop.is_set()):
            return True
        if len(pool) >= _CFPROXY_MIN_VALID_DOMAINS:
            balancer.update_domains_list(pool)
            log.info("CF proxy domain pool updated from GitHub (%d domains)", len(pool))
            return True

    if fetched:
        log.warning(
            "Ignoring fetched CF proxy domains due to low-quality payload "
            "(total=%d, valid=%d, required>=%d); keeping current domain pool",
            len(fetched), len(pool), _CFPROXY_MIN_VALID_DOMAINS,
        )
    else:
        log.warning(
            "CF proxy domain refresh failed or empty response; "
            "keeping current domain pool",
        )
    return True


_refresh_stop: threading.Event = threading.Event()


def stop_cfproxy_domain_refresh() -> None:
    with _refresh_state_lock:
        _refresh_stop.set()


def start_cfproxy_domain_refresh() -> None:
    global _refresh_stop
    with _refresh_state_lock:
        _refresh_stop.set()
        _refresh_stop = threading.Event()
        stop = _refresh_stop
        balancer.update_domains_list(CFPROXY_DEFAULT_DOMAINS)

    def _loop():
        while not stop.is_set():
            attempted = refresh_cfproxy_domains(stop)
            # An older generation can temporarily own the one fetch slot.
            # Retry that local busy condition, not the failed HTTP request.
            if stop.wait(timeout=3600 if attempted else 1):
                return

    try:
        threading.Thread(target=_loop, daemon=True, name='cfproxy-domains-refresh').start()
    except RuntimeError:
        stop.set()
        log.warning("CF proxy domain refresh worker could not start; keeping defaults")


def parse_dc_ip_list(dc_ip_list: List[str]) -> Dict[int, str]:
    dc_redirects: Dict[int, str] = {}
    for entry in dc_ip_list:
        if ':' not in entry:
            err = ValueError(
                f"Invalid --dc-ip format {entry!r}, expected DC:IP")
            err.entry = entry
            err.kind = "format"
            raise err
        dc_s, ip_s = entry.split(':', 1)
        try:
            dc_n = int(dc_s)
            ip_s = require_direct_route(dc_n, ip_s)
        except (ValueError, OSError):
            err = ValueError(f"Invalid --dc-ip {entry!r}")
            err.entry = entry
            err.kind = "invalid"
            raise err from None
        dc_redirects[dc_n] = ip_s
    return dc_redirects
