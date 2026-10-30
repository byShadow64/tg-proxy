"""Strict verification of the public, signed backup release channel."""
from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Mapping
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAX_MANIFEST_BYTES = 128 * 1024
MAX_ASSET_BYTES = 512 * 1024 * 1024
ASSET_NAMES = frozenset({
    "TgWsProxy_windows.exe", "TgWsProxy_helper.zip", "SHA256SUMS.txt", "CHANGELOG.md",
})
_VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?")
_KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


def validate_https_url(url: str) -> str:
    """Reject ambiguous URLs before urllib or a redirect handler sees them."""
    if (not isinstance(url, str) or not url or len(url) > 4096
            or any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url):
        raise ValueError("Invalid update HTTPS URL")
    try:
        parts = urlsplit(url)
        if (parts.scheme != "https" or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.fragment or parts.port == 0):
            raise ValueError
        # Parsing .port also rejects invalid/out-of-range ports and broken IPv6.
        _ = parts.port
        parts.hostname.encode("idna")
    except (ValueError, UnicodeError):
        raise ValueError("Invalid update HTTPS URL") from None
    return url


def version_parts(version: str) -> tuple:
    if not isinstance(version, str) or len(version) > 128:
        raise ValueError("Invalid update version")
    match = _VERSION.fullmatch(version)
    if not match:
        raise ValueError("Invalid update version")
    prerelease = match[4]
    if prerelease is not None:
        identifiers = prerelease.split(".")
        if any(not p or (p.isdigit() and len(p) > 1 and p.startswith("0")) for p in identifiers):
            raise ValueError("Invalid update version")
    return tuple(int(match[i]) for i in (1, 2, 3)), prerelease


def version_gt(left: str, right: str) -> bool:
    """SemVer ordering, including stable versions after their prereleases."""
    a, ap = version_parts(left)
    b, bp = version_parts(right)
    if a != b:
        return a > b
    if ap is None or bp is None:
        return ap is None and bp is not None
    aa, bb = ap.split("."), bp.split(".")
    for x, y in zip(aa, bb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return int(x) > int(y)
        if x.isdigit() != y.isdigit():
            return not x.isdigit()
        return x > y
    return len(aa) > len(bb)


def canonical_message(schema: int, key_id: str, payload: dict) -> bytes:
    return json.dumps({"schema": schema, "key_id": key_id, "payload": payload},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate update manifest field")
        result[key] = value
    return result


def _exact_fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("Invalid update manifest schema")


def _timestamp(value):
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError("Invalid update manifest timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError("Invalid update manifest timestamp") from None


def verify_manifest(raw: bytes, trusted_keys: Mapping[str, str], *, now=None) -> dict:
    """Return new normalized release metadata only after signature verification.

    Private signing material and raw LogRecords are never part of this protocol.
    The schema and key identity are signed along with the complete payload.
    """
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Invalid update manifest size")
    try:
        envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _exact_fields(envelope, ("schema", "key_id", "payload", "signature"))
        schema, key_id, payload = envelope["schema"], envelope["key_id"], envelope["payload"]
        if type(schema) is not int or schema != 1 or not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise ValueError("Unsupported update manifest schema or key")
        if key_id not in trusted_keys:
            raise ValueError("Untrusted update signing key")
        key = base64.b64decode(trusted_keys[key_id], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(key) != 32 or len(signature) != 64:
            raise ValueError("Invalid update signature")
        Ed25519PublicKey.from_public_bytes(key).verify(signature, canonical_message(schema, key_id, payload))
    except (InvalidSignature, binascii.Error, UnicodeError, TypeError, KeyError, RecursionError):
        raise ValueError("Invalid update manifest signature or JSON") from None

    _exact_fields(payload, ("version", "published_at", "expires_at", "notes", "page_url", "assets"))
    version_parts(payload["version"])
    published, expires = _timestamp(payload["published_at"]), _timestamp(payload["expires_at"])
    current = now if now is not None else datetime.now(timezone.utc)
    if expires <= current or expires <= published or published > current + timedelta(minutes=5):
        raise ValueError("Expired or future update manifest")
    if not isinstance(payload["notes"], str) or len(payload["notes"]) > 32768:
        raise ValueError("Invalid update release notes")
    validate_https_url(payload["page_url"])
    source_assets = payload["assets"]
    if not isinstance(source_assets, list) or not 1 <= len(source_assets) <= len(ASSET_NAMES):
        raise ValueError("Invalid update assets")
    assets, names = [], set()
    for asset in source_assets:
        _exact_fields(asset, ("name", "url", "size", "sha256"))
        name, size, digest = asset["name"], asset["size"], asset["sha256"]
        if not isinstance(name, str) or name not in ASSET_NAMES or name in names:
            raise ValueError("Invalid or duplicate update asset name")
        if type(size) is not int or not 1 <= size <= MAX_ASSET_BYTES:
            raise ValueError("Invalid update asset size")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError("Invalid update asset checksum")
        validate_https_url(asset["url"])
        names.add(name)
        assets.append({"name": name, "url": asset["url"], "size": size,
                       "digest": "sha256:" + digest, "version": payload["version"], "source": "backup"})
    return {"latest": payload["version"], "html_url": payload["page_url"],
            "notes": payload["notes"], "published_at": payload["published_at"],
            "expires_at": payload["expires_at"], "assets": assets, "source": "backup"}
