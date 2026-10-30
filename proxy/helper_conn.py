"""Length-framed WebSocket adapter for a remote TG WS Helper."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ssl
import struct
import time
from typing import Optional

MAX_FRAME_SIZE = 16 * 1024 * 1024
HANDSHAKE_TIMEOUT = 15.0
FRAME_TIMEOUT = 120.0
_HEADER = struct.Struct(">I")


def normalize_fingerprint(value: str) -> str:
    normalized = value.lower().replace(":", "").replace(" ", "")
    if any(ch not in "0123456789abcdef" for ch in normalized):
        return ""
    return normalized


class HelperConnection:
    """Drop-in send/recv/close transport for ``bridge_ws_reencrypt``.

    The v2 client completes TLS and checks the certificate pin before it sends
    either the bearer token or the requested Telegram route.
    """

    def __init__(self, reader, writer, domain: str, host: str, port: int):
        self.reader = reader
        self.writer = writer
        self.domain = domain
        self.host = host
        self.port = port
        self._closed = False
        self.last_pong = time.monotonic()

    @classmethod
    async def connect_v2(cls, host: str, port: int, fingerprint: str,
                         token: str, domain: str) -> "HelperConnection":
        expected = normalize_fingerprint(fingerprint)
        if len(expected) != 64:
            raise ValueError("Helper TLS fingerprint must be a SHA-256 hex digest")
        if not token:
            raise ValueError("Helper token is not configured")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=None),
            timeout=HANDSHAKE_TIMEOUT,
        )
        conn = cls(reader, writer, domain, host, port)
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            certificate = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            actual = hashlib.sha256(certificate or b"").hexdigest()
            if not certificate or not hmac.compare_digest(actual, expected):
                raise ssl.SSLError("Helper certificate fingerprint mismatch")
            await conn._write_frame(token.encode("utf-8"), HANDSHAKE_TIMEOUT)
            await conn._write_frame(domain.encode("ascii"), HANDSHAKE_TIMEOUT)
            response = await conn._read_frame(HANDSHAKE_TIMEOUT)
            if response != b"OK":
                raise PermissionError("Helper rejected authorization or route")
            return conn
        except BaseException:
            await conn.close()
            raise

    @classmethod
    async def connect_legacy(cls, host: str, port: int,
                             domain: str) -> "HelperConnection":
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=HANDSHAKE_TIMEOUT)
        conn = cls(reader, writer, domain, host, port)
        try:
            await conn._write_frame(domain.encode("ascii"), HANDSHAKE_TIMEOUT)
        except BaseException:
            await conn.close()
            raise
        return conn

    async def _write_frame(self, data: bytes, timeout: float = FRAME_TIMEOUT) -> None:
        if len(data) > MAX_FRAME_SIZE:
            raise ValueError("Helper frame exceeds 16 MiB")
        self.writer.write(_HEADER.pack(len(data)) + data)
        await asyncio.wait_for(self.writer.drain(), timeout=timeout)

    async def _read_frame(self, timeout: float = FRAME_TIMEOUT, *,
                          allow_idle: bool = False) -> Optional[bytes]:
        if allow_idle:
            first = await self.reader.readexactly(1)
            header = first + await asyncio.wait_for(self.reader.readexactly(3), timeout=timeout)
        else:
            header = await asyncio.wait_for(self.reader.readexactly(4), timeout=timeout)
        size = _HEADER.unpack(header)[0]
        if size > MAX_FRAME_SIZE:
            raise ValueError("Helper frame exceeds 16 MiB")
        if allow_idle:
            body = bytearray()
            while len(body) < size:
                chunk = await asyncio.wait_for(self.reader.read(min(size - len(body), 64 * 1024)), timeout=timeout)
                if not chunk:
                    raise asyncio.IncompleteReadError(bytes(body), size)
                body.extend(chunk)
            return bytes(body)
        return await asyncio.wait_for(self.reader.readexactly(size), timeout=timeout)

    async def send(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionError("Helper connection closed")
        await self._write_frame(data)

    async def send_batch(self, parts: list) -> None:
        for part in parts:
            await self.send(part)

    async def send_ping(self) -> None:
        return

    async def recv(self) -> Optional[bytes]:
        if self._closed:
            return None
        try:
            data = await self._read_frame(FRAME_TIMEOUT, allow_idle=True)
            self.last_pong = time.monotonic()
            return data
        except asyncio.IncompleteReadError:
            self._closed = True
            return None
        except (ConnectionError, OSError, asyncio.TimeoutError):
            self._closed = True
            return None

    async def close(self) -> None:
        self._closed = True
        self.writer.close()
        try:
            await asyncio.wait_for(self.writer.wait_closed(), timeout=5)
        except Exception:
            pass
