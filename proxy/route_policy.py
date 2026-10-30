"""Destination bounds for Telegram routes, separate from configured relays.

CIDR snapshot: https://core.telegram.org/resources/cidr.txt, 2026-10-29.
This list is bundled, never fetched automatically. Update with reviewed Telegram
network changes. CF/Worker/Helper are separate intentional proxy transports,
not additions to Telegram's direct IP allowlist.
"""
from __future__ import annotations

import ipaddress
import re

TELEGRAM_CIDRS = (
    '91.108.56.0/22', '91.108.4.0/22', '91.108.8.0/22',
    '91.108.16.0/22', '91.108.12.0/22', '149.154.160.0/20',
    '91.105.192.0/23', '91.108.20.0/22', '185.76.151.0/24',
    '2001:b28:f23d::/48', '2001:b28:f23f::/48', '2001:67c:4e8::/48',
    '2001:b28:f23c::/48', '2a0a:f280::/32',
)
_TELEGRAM_NETWORKS = tuple(ipaddress.ip_network(value) for value in TELEGRAM_CIDRS)
_DIRECT_DCS = frozenset((1, 2, 3, 4, 5, 203))
_DNS_LABEL = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z')
_TELEGRAM_WS = re.compile(r'kws(?:[1-5]|203)(?:-1)?\.web\.telegram\.org\Z', re.ASCII)


def require_telegram_ip(value: str) -> str:
    """Require a literal Telegram IP, so validation cannot race a DNS lookup."""
    if not isinstance(value, str) or '%' in value:
        raise ValueError('Direct Telegram route requires an unscoped literal IP')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError('Direct Telegram route requires a literal IP') from None
    if not any(address.version == network.version and address in network
               for network in _TELEGRAM_NETWORKS):
        raise ValueError('Direct route IP is outside the Telegram CIDR catalog')
    return str(address)


def require_direct_route(dc: int, value: str) -> str:
    if type(dc) is not int or dc not in _DIRECT_DCS:
        raise ValueError('Unsupported direct Telegram DC')
    return require_telegram_ip(value)


def require_relay_hostname(value: str) -> str:
    """Require one DNS host, never a URL, port, path or userinfo injection."""
    if not isinstance(value, str) or not value.isascii() or len(value) > 253:
        raise ValueError('Relay requires an ASCII DNS hostname, not a URL or IP')
    labels = value.split('.')
    if (len(labels) < 2 or not all(_DNS_LABEL.fullmatch(label) for label in labels)
            or len(labels[-1]) < 2 or not any(ch.isalpha() for ch in labels[-1])):
        raise ValueError('Relay requires a DNS hostname without port, path or credentials')
    return value


def is_telegram_ws_domain(domain: str) -> bool:
    return isinstance(domain, str) and _TELEGRAM_WS.fullmatch(domain.lower()) is not None
