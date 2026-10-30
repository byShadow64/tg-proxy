#!/usr/bin/env python3
"""Authenticated TLS bridge from framed TCP to Telegram WebSocket routes.

Secure v2 listens on TCP/8444. The unauthenticated v1 protocol is disabled by
default and is exposed on TCP/8443 only with the explicit --allow-legacy flag.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import deque
import hmac
import inspect
import ipaddress
import logging
import signal
import ssl
import struct
import time
from pathlib import Path

import websockets
from websockets.exceptions import ConnectionClosedOK
from proxy.utils import WS_PATH, ws_domains

LOG = logging.getLogger("tg-helper")
MAX_FRAME_SIZE = 16 * 1024 * 1024
MAX_REGISTERED_FRAME_SIZE = 2 * 1024 * 1024
MAX_TOKEN_SIZE = 512
MAX_ROUTE_SIZE = 253
STREAM_BUFFER_LIMIT = 64 * 1024
HANDSHAKE_TIMEOUT = 15.0
FRAME_TIMEOUT = 120.0
CLOSE_TIMEOUT = 5.0
MAX_CONNECTIONS = 256
MAX_CONNECTIONS_PER_IP = 32
HEADER = struct.Struct(">I")
_UPSTREAM_OPTIONS = {
    "subprotocols": ["binary"],
    "origin": "https://web.telegram.org",
    "compression": None,
}
if "proxy" in inspect.signature(websockets.connect).parameters:
    # A helper must dial Telegram directly, independently of shell proxy envs.
    _UPSTREAM_OPTIONS["proxy"] = None


def _reject_legacy_redirect(_uri: str) -> None:
    raise ConnectionError("Telegram WebSocket redirects are not permitted")


def _telegram_connect(uri: str, **kwargs):
    """Keep the validated Telegram route for the entire opening handshake.

    websockets follows HTTP redirects by default, including another host or
    port. The route allowlist must not be bypassed by an upstream Location.
    These are the redirect hooks in the supported websockets 12-15 APIs;
    configure the connector before awaiting it (before any network I/O).
    """
    connection = websockets.connect(uri, **kwargs)
    if callable(getattr(connection, "process_redirect", None)):
        # New asyncio API (default since 14): return the original exception.
        connection.process_redirect = lambda exc: exc
    elif callable(getattr(connection, "handle_redirect", None)):
        # Legacy asyncio API (default in 12-13): abort before changing target.
        connection.handle_redirect = _reject_legacy_redirect
    else:
        raise RuntimeError("Unsupported WebSocket redirect policy API")
    return connection


def route_catalog() -> frozenset[str]:
    """Derive accepted target names from the current upstream route function."""
    return frozenset(
        domain.lower()
        for dc in (1, 2, 3, 4, 5, 203)
        for media in (False, True)
        for domain in ws_domains(dc, media)
    )


# Domains used by the previous TG Proxy helper client. Keep these names
# restricted to v1 compatibility; v2 accepts only the active upstream catalog.
LEGACY_ROUTE_COMPAT = frozenset({
    "zws2.web.telegram.org", "zws2-1.web.telegram.org",
    "zws4.web.telegram.org", "zws4-1.web.telegram.org",
})


async def read_frame(reader: asyncio.StreamReader,
                     timeout: float = FRAME_TIMEOUT, *,
                     max_size: int = MAX_FRAME_SIZE,
                     allow_idle: bool = False) -> bytes:
    # Established data streams may be quiet in one direction for any duration.
    # A started header and every body read still have a progress deadline.
    if allow_idle:
        first = await reader.readexactly(1)
        header = first + await asyncio.wait_for(reader.readexactly(3), timeout)
    else:
        header = await asyncio.wait_for(reader.readexactly(4), timeout)
    size = HEADER.unpack(header)[0]
    if size > max_size:
        raise ValueError("frame_too_large")
    if allow_idle:
        body = bytearray()
        while len(body) < size:
            chunk = await asyncio.wait_for(reader.read(min(size - len(body), STREAM_BUFFER_LIMIT)), timeout)
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(body), size)
            body.extend(chunk)
        return bytes(body)
    return await asyncio.wait_for(reader.readexactly(size), timeout)


async def write_frame(writer: asyncio.StreamWriter, data: bytes,
                      timeout: float = FRAME_TIMEOUT) -> None:
    if len(data) > MAX_FRAME_SIZE:
        raise ValueError("frame_too_large")
    writer.write(HEADER.pack(len(data)) + data)
    await asyncio.wait_for(writer.drain(), timeout)


class HelperServer:
    def __init__(self, token: str, *, pairing_store=None, certificate_digest: bytes | None = None,
                 registry_authorizer=None):
        self._token = token.encode("utf-8")
        if not 32 <= len(self._token) <= MAX_TOKEN_SIZE:
            raise ValueError("Helper token must contain 32 to 512 UTF-8 bytes")
        self._routes = route_catalog()
        self._legacy_routes = self._routes | LEGACY_ROUTE_COMPAT
        self._active = 0
        self._per_ip: dict[str, int] = {}
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task] = set()
        self._pairing_store = pairing_store
        self._certificate_digest = certificate_digest
        self._registry_authorizer = registry_authorizer
        if pairing_store is not None and (not isinstance(certificate_digest, bytes) or len(certificate_digest) != 32):
            raise ValueError("Pairing requires the loaded TLS certificate digest")
        self._pairing_attempts = deque()
        self._pairing_per_ip = {}

    def _admit_pairing(self, ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - 60
        while self._pairing_attempts and self._pairing_attempts[0][0] <= cutoff:
            _, previous = self._pairing_attempts.popleft()
            count = self._pairing_per_ip[previous] - 1
            if count:
                self._pairing_per_ip[previous] = count
            else:
                del self._pairing_per_ip[previous]
        if len(self._pairing_attempts) >= 120 or self._pairing_per_ip.get(ip, 0) >= 10:
            return False
        self._pairing_attempts.append((now, ip))
        self._pairing_per_ip[ip] = self._pairing_per_ip.get(ip, 0) + 1
        return True

    async def _pair(self, reader, writer, ip):
        from helper_pairing import DENIED, MAX_REQUEST

        response = DENIED
        if self._pairing_store is not None and self._admit_pairing(ip):
            try:
                request = await asyncio.wait_for(read_frame(reader, 5, max_size=MAX_REQUEST), 5)
                endpoint = writer.get_extra_info("sockname")
                response = await asyncio.wait_for(asyncio.to_thread(
                    self._pairing_store.redeem, request, self._certificate_digest,
                    self._token.decode("utf-8"), int(endpoint[1])), 2)
            except (ValueError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                pass
        await write_frame(writer, response, 5)

    def _admit(self, ip: str) -> bool:
        current = self._per_ip.get(ip, 0)
        if self._active >= MAX_CONNECTIONS or current >= MAX_CONNECTIONS_PER_IP:
            return False
        self._active += 1
        self._per_ip[ip] = current + 1
        return True

    def _release(self, ip: str) -> None:
        self._active = max(0, self._active - 1)
        current = self._per_ip.get(ip, 0) - 1
        if current <= 0:
            self._per_ip.pop(ip, None)
        else:
            self._per_ip[ip] = current

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter, *, secure: bool, _pre_admitted: bool = False) -> None:
        peer = writer.get_extra_info("peername")
        ip = str(peer[0]) if peer else "unknown"
        try:
            ip = str(ipaddress.ip_address(ip.split("%", 1)[0]))
        except ValueError:
            ip = "unknown"
        task = asyncio.current_task()
        if task:
            self._tasks.add(task)
        self._writers.add(writer)
        registry_device = None
        if not _pre_admitted and not self._admit(ip):
            LOG.warning("Rejected connection: concurrency limit reached")
            self._writers.discard(writer)
            if task:
                self._tasks.discard(task)
            # No admitted slot exists to bound a TLS close-notify wait here.
            writer.transport.abort()
            return

        try:
            if secure:
                token = await asyncio.wait_for(read_frame(
                    reader, HANDSHAKE_TIMEOUT, max_size=MAX_TOKEN_SIZE),
                                               HANDSHAKE_TIMEOUT)
                # Reserved pre-auth marker; pairing is opt-in and TLS-only.
                if token == b"TGPAIR1":
                    await self._pair(reader, writer, ip)
                    return
                if not hmac.compare_digest(token, self._token):
                    if self._registry_authorizer is not None and token.startswith(b"TGL1."):
                        try:
                            registry_device = self._registry_authorizer.acquire(token)
                        except (ValueError, OSError):
                            await write_frame(writer, b"NO", HANDSHAKE_TIMEOUT)
                            return
                    else:
                        await write_frame(writer, b"NO", HANDSHAKE_TIMEOUT)
                        return
                supplied_domain = await asyncio.wait_for(
                    read_frame(reader, HANDSHAKE_TIMEOUT, max_size=MAX_ROUTE_SIZE),
                    HANDSHAKE_TIMEOUT)
                domain = supplied_domain.decode("ascii", errors="strict").lower()
                if domain not in self._routes:
                    await write_frame(writer, b"NO", HANDSHAKE_TIMEOUT)
                    return
            else:
                supplied_domain = await asyncio.wait_for(
                    read_frame(reader, HANDSHAKE_TIMEOUT, max_size=MAX_ROUTE_SIZE),
                    HANDSHAKE_TIMEOUT)
                domain = supplied_domain.decode("ascii", errors="strict").lower()
                if domain not in self._legacy_routes:
                    return

            if registry_device is None:
                await self._relay(reader, writer, domain, secure=secure)
            else:
                await self._relay(reader, writer, domain, secure=secure, registry_device=registry_device)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                ConnectionError, OSError, UnicodeError, ValueError, ConnectionClosedOK) as exc:
            reason = str(exc) if str(exc) == "frame_too_large" else type(exc).__name__
            LOG.debug("Connection closed (%s)", reason)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Exception strings can contain request data, so only log the type.
            LOG.warning("Relay failed (%s)", type(exc).__name__)
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), CLOSE_TIMEOUT)
            except (OSError, asyncio.TimeoutError, asyncio.CancelledError):
                writer.transport.abort()
            finally:
                if registry_device is not None:
                    self._registry_authorizer.release(registry_device)
                if not _pre_admitted:
                    self._release(ip)
                self._writers.discard(writer)
                if task:
                    self._tasks.discard(task)

    async def _relay(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter, domain: str,
                     *, secure: bool = False, registry_device: str | None = None) -> None:
        queue_options = dict(max_queue=1, write_limit=STREAM_BUFFER_LIMIT) if registry_device is not None else {}
        async with _telegram_connect(
            f"wss://{domain}{WS_PATH}", open_timeout=HANDSHAKE_TIMEOUT,
            close_timeout=5, ping_interval=20, ping_timeout=20,
            max_size=MAX_REGISTERED_FRAME_SIZE if registry_device is not None else MAX_FRAME_SIZE,
            **queue_options, **_UPSTREAM_OPTIONS,
        ) as upstream:
            if upstream.subprotocol != "binary":
                raise ConnectionError("Telegram did not negotiate the binary subprotocol")
            if secure:
                await write_frame(writer, b"OK", HANDSHAKE_TIMEOUT)
            LOG.info("Telegram WebSocket ready: %s (%s)", domain,
                     "TLS v2" if secure else "legacy v1")

            async def client_to_upstream() -> None:
                while True:
                    payload = await read_frame(reader, FRAME_TIMEOUT, allow_idle=True,
                        max_size=MAX_REGISTERED_FRAME_SIZE if registry_device is not None else MAX_FRAME_SIZE)
                    if registry_device is not None:
                        if not payload:
                            raise ValueError("empty_registered_frame")
                        await self._registry_authorizer.throttle_message(registry_device, len(payload))
                    # An async iterable makes even a 64-byte init fragmented.
                    # Telegram requires the same single binary frame in both
                    # authentication modes; charge the bounded message first.
                    await upstream.send(payload)

            async def upstream_to_client() -> None:
                if registry_device is None:
                    async for payload in upstream:
                        if isinstance(payload, str):
                            raise ValueError("unexpected_text_frame")
                        await write_frame(writer, payload)
                else:
                    from proxy.registry_helper import MIN_REGISTERED_MESSAGE_COST
                    while True:
                        payload = await upstream.recv(decode=False)
                        if not isinstance(payload, bytes):
                            raise ValueError("unexpected_text_frame")
                        if len(payload) < MIN_REGISTERED_MESSAGE_COST:
                            await self._registry_authorizer.throttle_message(registry_device, len(payload))
                            await write_frame(writer, payload)
                            continue
                        for offset in range(0, max(1, len(payload)), STREAM_BUFFER_LIMIT):
                            part = memoryview(payload)[offset:offset + STREAM_BUFFER_LIMIT]
                            await self._registry_authorizer.throttle(registry_device, len(part))
                            await write_frame(writer, part)

            tasks = [asyncio.create_task(client_to_upstream()),
                     asyncio.create_task(upstream_to_client())]
            try:
                completed, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                # Surface a completed pump's exception to the safe type-only
                # connection handler; gather(return_exceptions=True) below is
                # solely cleanup, and must not hide an upstream protocol error.
                for task in reversed(tasks):
                    if task in completed and not task.cancelled():
                        error = task.exception()
                        if error is not None:
                            raise error
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

    async def close_clients(self) -> None:
        for writer in tuple(self._writers):
            writer.close()
        tasks = [task for task in self._tasks if task is not asyncio.current_task()]
        if tasks:
            await asyncio.wait_for(asyncio.gather(
                *(asyncio.wait_for(task, 5) for task in tasks),
                return_exceptions=True,
            ), timeout=6)


def _read_token(path: Path) -> str:
    token = path.read_text(encoding="utf-8").strip()
    if not 32 <= len(token.encode("utf-8")) <= MAX_TOKEN_SIZE:
        raise ValueError("Token file must contain 32 to 512 UTF-8 bytes")
    return token


async def run(args: argparse.Namespace) -> None:
    if args.bind is None:
        args.bind = ["0.0.0.0"]
    token = _read_token(Path(args.token_file))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.tls_cert, args.tls_key)
    pairing_store = None
    certificate_digest = None
    if (getattr(args, "registry_config", None) is None) != (getattr(args, "registry_public_key", None) is None):
        raise ValueError("Registry configuration and trust key are required together")
    if getattr(args, "pairing_store", None) or getattr(args, "registry_config", None):
        from helper_pairing import PairingStore, certificate_digest as digest_leaf
        certificate_digest = digest_leaf(Path(args.tls_cert).read_text(encoding="ascii"))
        if getattr(args, "pairing_store", None):
            pairing_store = PairingStore(args.pairing_store)
    registry_authorizer = None
    if getattr(args, "registry_config", None):
        from proxy.registry_helper import RegistryLeaseAuthorizer
        registry_authorizer = RegistryLeaseAuthorizer(Path(args.registry_public_key), Path(args.registry_config),
            certificate_digest, port=args.secure_port,
            device_rate=getattr(args, "registry_device_rate", 4 * 1024 * 1024),
            shared_rate=getattr(args, "registry_shared_rate", 16 * 1024 * 1024),
            max_registered_connections=getattr(args, "registry_max_connections", 32))
    helper = HelperServer(token, pairing_store=pairing_store, certificate_digest=certificate_digest,
                          registry_authorizer=registry_authorizer)
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stopping.set)
        except (NotImplementedError, RuntimeError):
            pass
    if hasattr(signal, "SIGHUP"):
        try:
            loop.add_signal_handler(signal.SIGHUP, lambda: LOG.info(
                "SIGHUP received; journald manages log rotation"))
        except (NotImplementedError, RuntimeError):
            pass

    if args.secure_port == args.legacy_port:
        raise ValueError("Secure and legacy endpoints must use different ports")
    servers = await create_listener_servers(helper, args, tls)
    secure_server = servers[0]

    for server in servers:
        for sock in server.sockets or ():
            LOG.info("Listening on %s:%s (%s)", *sock.getsockname()[:2],
                     "TLS v2" if server is secure_server else "legacy v1")
    if args.allow_legacy:
        LOG.warning("Legacy unauthenticated protocol enabled on port %d",
                    args.legacy_port)

    try:
        await stopping.wait()
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))
        await helper.close_clients()


async def create_listener_servers(helper: HelperServer, args: argparse.Namespace,
                                  tls: ssl.SSLContext):
    async def admitted_tls(reader, writer, ip):
        # The slot covers the TCP socket, TLS handshake, authentication, relay
        # and shutdown, rather than only the authenticated application task.
        task = asyncio.current_task()
        raw_transport = writer.transport
        try:
            upgrade = getattr(writer, "start_tls", None)
            if callable(upgrade):
                await upgrade(tls, ssl_handshake_timeout=HANDSHAKE_TIMEOUT)
            else:
                # Ubuntu 22.04's Python 3.10 has loop.start_tls but not the
                # StreamWriter convenience API (added in 3.11). Keep the same
                # existing stream/protocol and replace only their transport.
                await writer.drain()
                protocol = raw_transport.get_protocol()
                transport = await asyncio.get_running_loop().start_tls(
                    raw_transport, protocol, tls, server_side=True,
                    ssl_handshake_timeout=HANDSHAKE_TIMEOUT)
                if transport is None:
                    raise ConnectionError("tls_not_established")
                writer._transport = transport
                protocol._transport = transport
                protocol._over_ssl = True
            if writer.transport is None or writer.get_extra_info("ssl_object") is None:
                raise ConnectionError("tls_not_established")
            await helper.handle(reader, writer, secure=True, _pre_admitted=True)
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError, ConnectionError, asyncio.TimeoutError):
            pass  # No peer data or TLS exception details enter the journal.
        finally:
            transport = writer.transport or raw_transport
            if transport is not None:
                transport.abort()
                if writer.transport is None:
                    # StreamWriter.start_tls may assign None when a peer
                    # closes before upgrade. Retain the closed transport for
                    # StreamWriter.__del__ on affected Python versions.
                    writer._transport = transport
            helper._release(ip)
            helper._writers.discard(writer)
            if task:
                helper._tasks.discard(task)

    def accepted_tcp(reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            ip = str(ipaddress.ip_address(str(peer[0]).split("%", 1)[0])) if peer else "unknown"
        except ValueError:
            ip = "unknown"
        if not helper._admit(ip):
            writer.transport.abort()
            return
        try:
            # Pause synchronously in connection_made: otherwise an eager
            # ClientHello could enter StreamReader's plaintext buffer before
            # start_tls installs SSLProtocol, leaving a valid handshake stuck.
            writer.transport.pause_reading()
            task = asyncio.create_task(admitted_tls(reader, writer, ip))
            helper._tasks.add(task)
            helper._writers.add(writer)
        except BaseException:
            helper._release(ip)
            writer.transport.abort()
            raise

    secure_server = await asyncio.start_server(
        accepted_tcp, args.bind, args.secure_port,
        limit=STREAM_BUFFER_LIMIT,
    )
    servers = [secure_server]
    try:
        if args.allow_legacy:
            legacy_server = await asyncio.start_server(
                lambda r, w: helper.handle(r, w, secure=False), args.bind,
                args.legacy_port, limit=STREAM_BUFFER_LIMIT,
            )
            servers.append(legacy_server)
    except BaseException:
        # Startup is transactional: a failed/cancelled second bind must not
        # leave a TLS listener accepting clients after startup was reported failed.
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))
        raise
    return servers


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", action="append", help="listener address; repeat for IPv4 and IPv6 (default IPv4)")
    parser.add_argument("--secure-port", type=int, default=8444)
    parser.add_argument("--legacy-port", type=int, default=8443)
    parser.add_argument("--allow-legacy", action="store_true",
                        help="temporarily listen for unauthenticated v1 clients on --legacy-port")
    parser.add_argument("--tls-cert", required=True)
    parser.add_argument("--tls-key", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--pairing-store", help="enable one-use owner pairing with this private SQLite store")
    parser.add_argument("--registry-config", help="enable optional registry leases with this signed private configuration")
    parser.add_argument("--registry-public-key", help="owner-provisioned fixed P256 central verification key PEM")
    parser.add_argument("--registry-device-rate", type=int, default=4 * 1024 * 1024, help="registered bytes/s per device")
    parser.add_argument("--registry-shared-rate", type=int, default=16 * 1024 * 1024, help="registered bytes/s across all devices")
    parser.add_argument("--registry-max-connections", type=int, default=32, help="registered session pool; private clients retain old limits")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
