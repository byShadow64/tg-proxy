"""Bounded, cancellable pairing client. Call from a worker, never the Tk thread."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import hmac
import ipaddress
import secrets
import ssl
import struct
import threading

try:
    from helper_pairing import (MAGIC, MAX_PAYLOAD, MAX_RESPONSE, b64decode, b64encode, client_proof,
                                json_bytes, parse_code, parse_json, server_proof)
except ModuleNotFoundError:  # Installed wheels keep standalone sources here.
    from helper_payload_src.helper_pairing import (MAGIC, MAX_PAYLOAD, MAX_RESPONSE, b64decode, b64encode,
        client_proof, json_bytes, parse_code, parse_json, server_proof)


class PairingError(Exception):
    """No verified configuration was obtained. Remote details are never exposed."""


class PairingCancelled(PairingError):
    pass


@dataclass(frozen=True)
class PairingResult:
    host: str = field(repr=False)
    port: int = field(repr=False)
    tls_fingerprint: str = field(repr=False)
    token: str = field(repr=False)


def parse_endpoint(value: str, port: int = 8444) -> tuple[str, int]:
    """Accept a literal IP, IPv4:port or [IPv6]:port; never a URL or DNS name."""
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError("invalid_pairing_address")
    host = value.strip()
    if host.startswith("["):
        end = host.find("]")
        if end < 0:
            raise ValueError("invalid_pairing_address")
        suffix = host[end + 1:]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isascii() or not suffix[1:].isdigit():
                raise ValueError("invalid_pairing_address")
            port = int(suffix[1:])
        host = host[1:end]
    elif host.count(":") == 1 and "." in host:
        host, supplied = host.rsplit(":", 1)
        if not supplied.isascii() or not supplied.isdigit():
            raise ValueError("invalid_pairing_address")
        port = int(supplied)
    if "%" in host or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid_pairing_address")
    return str(ipaddress.ip_address(host)), port


def verify_response(response: bytes, *, identifier: str, key: bytes,
                    nonce: bytes, certificate: bytes, host: str, port: int) -> PairingResult:
    value = parse_json(response, maximum=MAX_RESPONSE)
    if set(value) != {"v", "nonce", "payload", "proof"}:
        raise ValueError("invalid_pairing_data")
    server_nonce = b64decode(value["nonce"], 32)
    payload = b64decode(value["payload"], maximum=MAX_PAYLOAD)
    proof = b64decode(value["proof"], 32)
    expected = server_proof(key, identifier, nonce, server_nonce, certificate, payload)
    if not hmac.compare_digest(proof, expected):
        raise ValueError("invalid_pairing_proof")
    # Do not parse, use or persist the token before authenticating raw payload.
    config = parse_json(payload, maximum=MAX_PAYLOAD)
    if set(config) != {"v", "port", "fingerprint", "token"}:
        raise ValueError("invalid_pairing_data")
    if (config["fingerprint"] != certificate.hex() or type(config["port"]) is not int
            or not 1 <= config["port"] <= 65535 or not isinstance(config["token"], str)
            or not 32 <= len(config["token"].encode("utf-8")) <= 512
            or config["token"] != config["token"].strip()
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in config["token"])):
        raise ValueError("invalid_pairing_data")
    # Keep the reachable endpoint supplied by the owner (NAT may map ports).
    return PairingResult(host=host, port=port, tls_fingerprint=certificate.hex(), token=config["token"])


async def _exchange(host, port, code):
    identifier, key = parse_code(code)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    writer = None
    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=context, server_hostname="",
                                                      ssl_handshake_timeout=8, limit=8192)
        tls = writer.get_extra_info("ssl_object")
        der = tls.getpeercert(binary_form=True) if tls else None
        if not der:
            raise ValueError("missing_pairing_certificate")
        certificate = hashlib.sha256(der).digest()
        nonce = secrets.token_bytes(32)
        request = json_bytes(dict(v=1, id=identifier, nonce=b64encode(nonce),
                                  proof=b64encode(client_proof(key, identifier, nonce, certificate))))
        # Neither the owner code, its secret nor the bearer token is sent.
        writer.write(struct.pack(">I", len(MAGIC)) + MAGIC + struct.pack(">I", len(request)) + request)
        await writer.drain()
        size = struct.unpack(">I", await reader.readexactly(4))[0]
        if not 1 <= size <= MAX_RESPONSE:
            raise ValueError("invalid_pairing_data")
        response = await reader.readexactly(size)
        return verify_response(response, identifier=identifier, key=key, nonce=nonce,
                               certificate=certificate, host=host, port=port)
    finally:
        if writer:
            # No unbounded TLS close-notify wait on cancellation or hostile peer.
            writer.close()
            if writer.transport:
                writer.transport.abort()


async def _run(host, port, code, timeout, cancel_event):
    exchange = asyncio.create_task(_exchange(host, port, code))
    deadline = asyncio.get_running_loop().time() + timeout
    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise PairingCancelled("Pairing cancelled")
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise PairingError("Pairing failed")
            done, _ = await asyncio.wait((exchange,), timeout=min(0.05, remaining))
            if done:
                if cancel_event is not None and cancel_event.is_set():
                    raise PairingCancelled("Pairing cancelled")
                return await exchange
    finally:
        exchange.cancel()
        await asyncio.gather(exchange, return_exceptions=True)


def pair_helper(host: str, code: str, port: int = 8444, *, timeout: float = 12.0,
                cancel_event: threading.Event | None = None) -> PairingResult:
    try:
        host, port = parse_endpoint(host, port)
        parse_code(code)
        if not 0 < timeout <= 30:
            raise ValueError("invalid_pairing_timeout")
        return asyncio.run(_run(host, port, code, timeout, cancel_event))
    except PairingCancelled:
        raise
    except Exception:
        # No server bytes, code, token or network exception text in UI/logs.
        raise PairingError("Pairing failed") from None
