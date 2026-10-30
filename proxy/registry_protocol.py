"""Registry v1 wire primitives. Public enrollment is not hardware attestation.

All private keys are supplied by the caller. Nothing in this module enrolls a
server, contacts the network, or contains a production trust anchor.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
import secrets
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

MAX_JSON = 8192
LEASE_TTL = 600
CHALLENGE_TTL = 60
ACCESS = "registered-device-public"
PROTOCOL = "helper-v2-lease"
DEVICE_CONTEXT = b"TGPROXY_REGISTRY_DEVICE_V1\0"
DESCRIPTOR_CONTEXT = b"TGPROXY_REGISTRY_DESCRIPTOR_V1\0"
CONFIG_CONTEXT = b"TGPROXY_REGISTRY_CONFIG_V1\0"
LEASE_CONTEXT = b"TGPROXY_REGISTRY_LEASE_V1\0"
ENROLL_CONTEXT = b"TGPROXY_HELPER_ENROLL_V1\0"
LEASE_STRUCT = struct.Struct(">B16s32s32sQQ16s")
TOKEN_PREFIX = "TGL1."
_HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class RegistryError(ValueError):
    """A fixed safe error code; never echo request bytes or credentials."""


def b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64decode(value, size: int | None = None, *, maximum: int = MAX_JSON) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum * 2 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise RegistryError("invalid_data")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        raise RegistryError("invalid_data") from None
    if len(raw) > maximum or (size is not None and len(raw) != size) or b64encode(raw) != value:
        raise RegistryError("invalid_data")
    return raw


def json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def parse_json(raw: bytes, *, keys: set[str] | None = None, maximum: int = MAX_JSON) -> dict:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise RegistryError("invalid_data")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RegistryError("invalid_data")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(RegistryError("invalid_data")))
    except (ValueError, UnicodeError, RecursionError):
        raise RegistryError("invalid_data") from None
    if not isinstance(value, dict) or type(value.get("v")) is not int or value["v"] != 1 or (keys is not None and set(value) != keys):
        raise RegistryError("invalid_data")
    return value


def canonical_ip(value: str) -> str:
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        raise RegistryError("invalid_ip")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise RegistryError("invalid_ip") from None
    if address.is_unspecified or address.is_multicast:
        raise RegistryError("invalid_ip")
    return str(address)


def public_key_der(key) -> bytes:
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise RegistryError("invalid_key")
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def encode_public_key(key) -> str:
    return b64encode(public_key_der(key))


def decode_public_key(value: str):
    raw = b64decode(value, maximum=128)
    try:
        key = serialization.load_der_public_key(raw)
        if public_key_der(key) != raw:
            raise RegistryError("invalid_key")
        return key
    except (ValueError, TypeError):
        raise RegistryError("invalid_key") from None


def device_id(key) -> str:
    return hashlib.sha256(public_key_der(key)).hexdigest()


def _signature(raw: bytes) -> bytes:
    try:
        if not 8 <= len(raw) <= 72:
            raise ValueError()
        r, s = utils.decode_dss_signature(raw)
        if not 0 < r < _ORDER or not 0 < s < _ORDER or utils.encode_dss_signature(r, s) != raw:
            raise ValueError()
        return raw
    except ValueError:
        raise RegistryError("invalid_signature") from None


def sign_bytes(key, context: bytes, payload: bytes) -> bytes:
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise RegistryError("invalid_key")
    return key.sign(context + payload, ec.ECDSA(hashes.SHA256()))


def verify_bytes(key, context: bytes, payload: bytes, signature: bytes) -> None:
    public_key_der(key)
    try:
        key.verify(_signature(signature), context + payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise RegistryError("invalid_signature") from None


def proof_payload(public_key, purpose: str, target: str, challenge: str) -> bytes:
    b64decode(challenge, 32)
    if purpose not in {"register", "lease", "helper", "enroll", "helper-disable"} or not isinstance(target, str) or len(target) > 45:
        raise RegistryError("invalid_data")
    if purpose == "register" and target != "":
        raise RegistryError("invalid_data")
    if purpose in {"lease", "enroll"} and target != canonical_ip(target):
        raise RegistryError("invalid_ip")
    if purpose in {"helper", "helper-disable"}:
        b64decode(target, 16)
    return json_bytes(dict(v=1, device_id=device_id(public_key), purpose=purpose, target=target, challenge=challenge))


def make_device_proof(private_key, purpose: str, target: str, challenge: str) -> dict:
    key = private_key.public_key()
    signature = sign_bytes(private_key, DEVICE_CONTEXT, proof_payload(key, purpose, target, challenge))
    return dict(v=1, public_key=encode_public_key(key), purpose=purpose, target=target,
                challenge=challenge, signature=b64encode(signature))


def sign_envelope(payload: dict, private_key, *, context: bytes = DESCRIPTOR_CONTEXT) -> dict:
    raw = json_bytes(payload)
    if len(raw) > 4096:
        raise RegistryError("invalid_data")
    return dict(v=1, payload=b64encode(raw), signature=b64encode(sign_bytes(private_key, context, raw)))


def verify_envelope(envelope: dict, public_key, *, context: bytes = DESCRIPTOR_CONTEXT) -> dict:
    envelope = parse_json(json_bytes(envelope), keys={"v", "payload", "signature"})
    payload = b64decode(envelope["payload"], maximum=4096)
    verify_bytes(public_key, context, payload, b64decode(envelope["signature"], maximum=72))
    result = parse_json(payload, maximum=4096)
    if json_bytes(result) != payload:
        raise RegistryError("invalid_data")
    return result


def _times(iat, exp, now: float | None) -> None:
    now = time.time() if now is None else now
    if (type(iat) is not int or type(exp) is not int or iat < 0 or not iat < exp <= iat + LEASE_TTL
            or iat > now + 30 or exp <= now):
        raise RegistryError("expired")


def verify_descriptor(envelope: dict, public_key, expected_ip: str, *, now: float | None = None) -> dict:
    value = verify_envelope(envelope, public_key)
    if set(value) != {"v", "helper_id", "ip", "port", "fingerprint", "iat", "exp", "protocol", "access"}:
        raise RegistryError("invalid_data")
    b64decode(value["helper_id"], 16)
    if (value["ip"] != canonical_ip(expected_ip) or value["ip"] != canonical_ip(value["ip"])
            or type(value["port"]) is not int or not 1 <= value["port"] <= 65535
            or not isinstance(value["fingerprint"], str) or not _HEX.fullmatch(value["fingerprint"])
            or value["protocol"] != PROTOCOL or value["access"] != ACCESS):
        raise RegistryError("invalid_data")
    _times(value["iat"], value["exp"], now)
    return value


@dataclass(frozen=True)
class LeaseClaims:
    helper_id: str
    device_id: str
    fingerprint: str
    iat: int
    exp: int
    lease_id: str


def issue_lease(private_key, helper_id: str, device: str, fingerprint: str, *, now: int | None = None, ttl: int = LEASE_TTL) -> str:
    if type(ttl) is not int or not 1 <= ttl <= LEASE_TTL or not _HEX.fullmatch(device) or not _HEX.fullmatch(fingerprint):
        raise RegistryError("invalid_data")
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < 0:
        raise RegistryError("invalid_data")
    payload = LEASE_STRUCT.pack(1, b64decode(helper_id, 16), bytes.fromhex(device), bytes.fromhex(fingerprint),
                                now, now + ttl, secrets.token_bytes(16))
    return TOKEN_PREFIX + b64encode(payload) + "." + b64encode(sign_bytes(private_key, LEASE_CONTEXT, payload))


def verify_lease(token: str, public_key, *, helper_id: str | None = None, fingerprint: str | None = None,
                 device: str | None = None, now: float | None = None) -> LeaseClaims:
    if not isinstance(token, str) or len(token) > 512 or not token.startswith(TOKEN_PREFIX):
        raise RegistryError("invalid_lease")
    parts = token[len(TOKEN_PREFIX):].split(".")
    if len(parts) != 2:
        raise RegistryError("invalid_lease")
    payload = b64decode(parts[0], LEASE_STRUCT.size)
    verify_bytes(public_key, LEASE_CONTEXT, payload, b64decode(parts[1], maximum=72))
    version, hid, did, pin, iat, exp, nonce = LEASE_STRUCT.unpack(payload)
    claims = LeaseClaims(b64encode(hid), did.hex(), pin.hex(), iat, exp, b64encode(nonce))
    if (version != 1 or (helper_id is not None and claims.helper_id != helper_id)
            or (fingerprint is not None and claims.fingerprint != fingerprint)
            or (device is not None and claims.device_id != device)):
        raise RegistryError("invalid_lease")
    _times(iat, exp, now)
    return claims


def verify_helper_config(envelope: dict, public_key, *, now: float | None = None) -> dict:
    value = verify_envelope(envelope, public_key, context=CONFIG_CONTEXT)
    if set(value) != {"v", "helper_id", "ip", "port", "fingerprint", "iat", "exp", "enabled", "max_device_connections", "access"}:
        raise RegistryError("invalid_data")
    b64decode(value["helper_id"], 16)
    if (value["ip"] != canonical_ip(value["ip"]) or type(value["port"]) is not int or not 1 <= value["port"] <= 65535
            or not isinstance(value["fingerprint"], str) or not _HEX.fullmatch(value["fingerprint"])
            or type(value["enabled"]) is not bool or type(value["max_device_connections"]) is not int
            or not 1 <= value["max_device_connections"] <= 32 or value["access"] != ACCESS):
        raise RegistryError("invalid_data")
    _times(value["iat"], value["exp"], now)
    return value
