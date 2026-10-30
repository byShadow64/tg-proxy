import os
import logging
import base64
import hashlib
import hmac
import ipaddress
import ssl
import struct
import asyncio
import socket as _socket

from typing import List, Optional, Tuple
from .config import proxy_config
from .route_policy import (is_telegram_ws_domain, require_relay_hostname,
                           require_telegram_ip)
from .utils import create_ssl_context, ws_domains
from cryptography import x509

log = logging.getLogger('tg-mtproto-proxy')


_st_BB = struct.Struct('>BB')
_st_BBH = struct.Struct('>BBH')
_st_BBQ = struct.Struct('>BBQ')
_st_BB4s = struct.Struct('>BB4s')
_st_BBH4s = struct.Struct('>BBH4s')
_st_BBQ4s = struct.Struct('>BBQ4s')
_st_H = struct.Struct('>H')
_st_Q = struct.Struct('>Q')

_XOR_TABLES = tuple(bytes(value ^ key for value in range(256)) for key in range(256))

_ssl_ctx = create_ssl_context()
_ssl_ctx_fronting = create_ssl_context(check_hostname=False)
_TELEGRAM_FRONTED_ORIGINS = frozenset(
    domain for dc in (1, 2, 3, 4, 5, 203) for media in (False, True)
    for domain in ws_domains(dc, media)
)


def _verify_fronted_identity(writer, domain: str) -> None:
    """The TLS SNI may be camouflage; the cert must identify the trusted service.

    OpenSSL still verifies the CA chain via CERT_REQUIRED. A different SNI
    cannot disable endpoint authentication or make any CA-issued cert valid.
    """
    ssl_object = writer.get_extra_info('ssl_object')
    der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
    try:
        names = x509.load_der_x509_certificate(der).extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        try:
            address = ipaddress.ip_address(domain)
        except ValueError:
            expected = domain.rstrip('.').encode('idna').decode('ascii').lower()
            identities = {expected}
            # Telegram's default virtual host presents a telegram.org cert
            # when camouflage SNI is used. This exception is restricted to
            # our fixed Telegram routes, never arbitrary configured origins.
            if expected in _TELEGRAM_FRONTED_ORIGINS:
                identities.add('telegram.org')
            for expected in identities:
                for name in names.get_values_for_type(x509.DNSName):
                    candidate = name.rstrip('.').lower()
                    if candidate == expected:
                        return
                    # Only a whole leftmost label, with no top-level wildcard.
                    if (candidate.startswith('*.') and candidate.count('*') == 1
                            and candidate.count('.') >= 2
                            and expected.count('.') == candidate.count('.')
                            and expected.split('.', 1)[1] == candidate[2:]):
                        return
        else:
            if address in names.get_values_for_type(x509.IPAddress):
                return
    except (ValueError, TypeError, x509.ExtensionNotFound):
        pass
    raise ssl.SSLCertVerificationError('Fronted certificate does not identify the WebSocket origin')

class WsHandshakeError(Exception):
    def __init__(self, status_code: int, status_line: str,
                 headers: Optional[dict] = None, location: Optional[str] = None):
        self.status_code = status_code
        self.status_line = status_line
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {status_line}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


def _xor_mask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    n = len(data)
    if n >= 512:
        masked = bytearray(data)
        for offset in range(4):
            masked[offset::4] = masked[offset::4].translate(_XOR_TABLES[mask[offset]])
        return bytes(masked)
    mask_rep = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, 'big') ^
            int.from_bytes(mask_rep, 'big')).to_bytes(n, 'big')


def set_sock_opts(transport, buffer_size):
    sock = transport.get_extra_info('socket')
    if sock is None:
        return
    
    try:
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    
    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, buffer_size)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, buffer_size)
    except OSError:
        pass


class RawWebSocket:
    __slots__ = ('reader', 'writer', '_closed', '_frag', '_fragmented')

    OP_CONT = 0x0
    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    MAX_MESSAGE_LEN = 16 * 1024 * 1024
    MAX_HANDSHAKE_HEADERS = 32 * 1024
    CLOSE_TIMEOUT = 1.0

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False
        self._frag = bytearray()
        self._fragmented = False

    @staticmethod
    async def connect(host: str, domain: str, timeout: float = 10.0,
                      path: str = '/apiws', *,
                      sni: Optional[str] = None, secure = True) -> 'RawWebSocket':
        # Client admission is not enough: warmup and diagnostics can dial
        # without a client. Enforce direct destination bounds at the socket.
        require_relay_hostname(domain)
        if is_telegram_ws_domain(domain):
            host = require_telegram_ip(host)
        else:
            # Configured CF/Worker transports remain allowed DNS endpoints;
            # reject URL/port/path injection before opening any connection.
            require_relay_hostname(host)
        ssl_context = _ssl_ctx_fronting if sni else _ssl_ctx

        if sni is None:
            sni = domain

        reader, writer = await asyncio.wait_for(
            (
                asyncio.open_connection(
                    host, 443,
                    ssl=ssl_context,
                    server_hostname=sni,
                )
                if secure
                else asyncio.open_connection(host, 80)
            ),
            timeout=min(timeout, 10),
        )
        
        try:
            if secure and ssl_context is _ssl_ctx_fronting:
                _verify_fronted_identity(writer, domain)
            set_sock_opts(writer.transport, proxy_config.buffer_size)

            ws_key = base64.b64encode(os.urandom(16)).decode()

            req = (
                f'GET {path} HTTP/1.1\r\n'
                f'Host: {domain}\r\n'
                f'Upgrade: websocket\r\n'
                f'Connection: Upgrade\r\n'
                f'Sec-WebSocket-Key: {ws_key}\r\n'
                f'Sec-WebSocket-Version: 13\r\n'
                f'Sec-WebSocket-Protocol: binary\r\n'
                f'\r\n'
            )

            deadline = asyncio.get_running_loop().time() + timeout
            writer.write(req.encode())
            await asyncio.wait_for(writer.drain(), timeout=timeout)

            response_lines: list[str] = []
            header_size = 0
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError()
                line = await asyncio.wait_for(reader.readline(),
                                              timeout=remaining)
                header_size += len(line)
                if header_size > RawWebSocket.MAX_HANDSHAKE_HEADERS:
                    raise WsHandshakeError(0, 'response headers too large')
                if not line:
                    raise WsHandshakeError(0, 'incomplete response headers')
                if line in (b'\r\n', b'\n'):
                    break
                response_lines.append(
                    line.decode('utf-8', errors='replace').rstrip('\r\n'))

            if not response_lines:
                raise WsHandshakeError(0, 'empty response')

            first_line = response_lines[0]
            parts = first_line.split(' ', 2)
            # An Upgrade response is an HTTP/1.1 response, not any line whose
            # second word happens to parse as 101. Keep the challenge checks
            # below too: a valid status line alone never proves WebSocket.
            if (len(parts) < 2 or parts[0] != 'HTTP/1.1'
                    or len(parts[1]) != 3 or not parts[1].isascii()
                    or not parts[1].isdecimal()):
                raise WsHandshakeError(0, 'invalid HTTP status line')
            status_code = int(parts[1])

            headers: dict[str, str] = {}
            for hl in response_lines[1:]:
                if ':' in hl:
                    k, v = hl.split(':', 1)
                    name = k.strip().lower()
                    if name in headers:
                        headers[name] += ',' + v.strip()
                    else:
                        headers[name] = v.strip()

            if status_code == 101:
                expected_accept = base64.b64encode(hashlib.sha1(
                    (ws_key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')
                ).digest()).decode('ascii')
                if (headers.get('upgrade', '').lower() != 'websocket'
                        or 'upgrade' not in {part.strip().lower() for part in
                                             headers.get('connection', '').split(',')}
                        or not hmac.compare_digest(headers.get('sec-websocket-accept', ''),
                                                   expected_accept)
                        or headers.get('sec-websocket-protocol') != 'binary'
                        or 'sec-websocket-extensions' in headers):
                    raise WsHandshakeError(101, 'invalid WebSocket upgrade')
                return RawWebSocket(reader, writer)

            raise WsHandshakeError(status_code, first_line, headers,
                                    location=headers.get('location'))
        except BaseException:
            writer.close()
            raise

    async def send(self, data: bytes):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        frame = self._build_frame(self.OP_BINARY, data, mask=True)
        self.writer.write(frame)
        await self.writer.drain()

    async def send_batch(self, parts: List[bytes]):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        for part in parts:
            self.writer.write(
                self._build_frame(self.OP_BINARY, part, mask=True))
        await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        while not self._closed:
            opcode, payload, fin = await self._read_frame()

            if opcode == self.OP_CLOSE:
                code, reason = self._parse_close(payload)
                log.debug("WS OP_CLOSE from upstream: code=%s reason=%r",
                          code, reason)
                await self._close(payload[:2] if payload else b'')
                return None

            if opcode == self.OP_PING:
                try:
                    self.writer.write(
                        self._build_frame(self.OP_PONG, payload, mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                continue

            if opcode == self.OP_PONG:
                continue

            if opcode in (self.OP_CONT, self.OP_BINARY):
                if opcode == self.OP_CONT:
                    if not self._fragmented:
                        raise ConnectionError("Unexpected WebSocket continuation")
                elif self._fragmented:
                    raise ConnectionError("Interleaved WebSocket messages")
                if fin and not self._fragmented:
                    return payload
                # Check before copying, and track empty first fragments too.
                if len(self._frag) + len(payload) > self.MAX_MESSAGE_LEN:
                    raise ConnectionError("WS message too large")
                self._frag.extend(payload)
                self._fragmented = not fin
                if not fin:
                    continue
                message = bytes(self._frag)
                self._frag.clear()
                return message
            continue
        return None

    async def close(self):
        await self._close(b'')

    async def _close(self, payload: bytes):
        if self._closed:
            return
        self._closed = True
        self._frag.clear()
        self._fragmented = False
        abort = True
        try:
            try:
                self.writer.write(
                    self._build_frame(self.OP_CLOSE, payload, mask=True))
                await asyncio.wait_for(self.writer.drain(), self.CLOSE_TIMEOUT)
                abort = False
            except Exception:
                pass
        finally:
            try:
                self.writer.close()
            except Exception:
                pass
            if abort:
                self._abort_transport()
            else:
                try:
                    await asyncio.wait_for(self.writer.wait_closed(), self.CLOSE_TIMEOUT)
                except asyncio.CancelledError:
                    self._abort_transport()
                    raise
                except Exception:
                    self._abort_transport()

    def _abort_transport(self):
        try:
            self.writer.transport.abort()
        except Exception:
            pass

    _WS_CLOSE_REASONS = {
        1000: 'normal', 1001: 'going_away', 1002: 'protocol_error',
        1003: 'unsupported_data', 1006: 'abnormal', 1007: 'bad_data',
        1008: 'policy_violation', 1009: 'too_big', 1010: 'missing_extension',
        1011: 'internal_error',
    }

    @classmethod
    def _parse_close(cls, payload: Optional[bytes]) -> Tuple[Optional[int], str]:
        if not payload or len(payload) < 2:
            return None, ''
        try:
            code = int.from_bytes(payload[:2], 'big')
            text = payload[2:].decode('utf-8', errors='replace')
            name = cls._WS_CLOSE_REASONS.get(code)
            return code, f"{text} ({name})" if name else text
        except Exception:
            return None, ''

    @staticmethod
    def _build_frame(opcode: int, data: bytes,
                     mask: bool = False) -> bytes:
        length = len(data)
        fb = 0x80 | opcode
        if not mask:
            if length < 126:
                return _st_BB.pack(fb, length) + data
            if length < 65536:
                return _st_BBH.pack(fb, 126, length) + data
            return _st_BBQ.pack(fb, 127, length) + data
        mask_key = os.urandom(4)
        masked = _xor_mask(data, mask_key)
        if length < 126:
            return _st_BB4s.pack(fb, 0x80 | length, mask_key) + masked
        if length < 65536:
            return _st_BBH4s.pack(fb, 0x80 | 126, length, mask_key) + masked
        return _st_BBQ4s.pack(fb, 0x80 | 127, length, mask_key) + masked

    async def _read_frame(self) -> Tuple[int, bytes, bool]:
        hdr = await self.reader.readexactly(2)
        fin = bool(hdr[0] & 0x80)
        opcode = hdr[0] & 0x0F
        # No extensions were negotiated. Servers must send unmasked frames;
        # this adapter's negotiated subprotocol carries binary messages only.
        if hdr[0] & 0x70 or hdr[1] & 0x80:
            raise ConnectionError("Invalid WebSocket frame flags")
        if opcode not in (self.OP_CONT, self.OP_BINARY, self.OP_CLOSE,
                          self.OP_PING, self.OP_PONG):
            raise ConnectionError("Unsupported WebSocket opcode")
        length = hdr[1] & 0x7F
        if opcode >= 0x8 and (not fin or length > 125):
            raise ConnectionError("Invalid WebSocket control frame")
        if length == 126:
            length = _st_H.unpack(await self.reader.readexactly(2))[0]
            if length < 126:
                raise ConnectionError("Non-minimal WebSocket frame length")
        elif length == 127:
            length = _st_Q.unpack(await self.reader.readexactly(8))[0]
            if length < 65536 or length >> 63:
                raise ConnectionError("Invalid WebSocket frame length")
        if length > self.MAX_MESSAGE_LEN:
            raise ConnectionError(f"WS frame too large: {length} bytes")
        payload = await self.reader.readexactly(length)
        if opcode == self.OP_CLOSE:
            if len(payload) == 1:
                raise ConnectionError("Invalid WebSocket close payload")
            if payload:
                code = _st_H.unpack(payload[:2])[0]
                if not (1000 <= code <= 1014 and code not in (1004, 1005, 1006)
                        or 3000 <= code <= 4999):
                    raise ConnectionError("Invalid WebSocket close code")
                try:
                    payload[2:].decode('utf-8')
                except UnicodeDecodeError:
                    raise ConnectionError("Invalid WebSocket close reason") from None
        return opcode, payload, fin
