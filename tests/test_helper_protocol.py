import asyncio
import datetime
import ipaddress
import ssl
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import websockets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from helper_server import (
    MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, MAX_FRAME_SIZE, MAX_TOKEN_SIZE,
    MAX_ROUTE_SIZE, STREAM_BUFFER_LIMIT, HelperServer,
    create_listener_servers, read_frame, route_catalog,
)
from proxy.helper_conn import HelperConnection


def _make_certificate(directory: Path, common_name="helper-test"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "server.crt"
    key_path = directory / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return cert_path, key_path, fingerprint


class HelperProtocolTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cert, self.key, self.fingerprint = _make_certificate(Path(self.temp.name))
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.load_cert_chain(self.cert, self.key)
        self.helper = HelperServer("a" * 64)
        self.relay_domains = []
        self.relay_started = asyncio.Event()

        async def fake_relay(reader, writer, domain, *, secure=False):
            self.relay_domains.append(domain)
            self.relay_started.set()
            if secure:
                from helper_server import write_frame
                await write_frame(writer, b"OK", 1)
            await reader.read()

        self.helper._relay = fake_relay
        self.server = await asyncio.start_server(
            lambda r, w: self.helper.handle(r, w, secure=True), "127.0.0.1", 0,
            ssl=self.server_context,
        )
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        await self.helper.close_clients()
        self.temp.cleanup()

    async def test_valid_token_and_certificate_pin_are_accepted(self):
        connection = await HelperConnection.connect_v2(
            "127.0.0.1", self.port, self.fingerprint, "a" * 64,
            "kws2.web.telegram.org",
        )
        await asyncio.wait_for(self.relay_started.wait(), 1)
        self.assertEqual(self.relay_domains, ["kws2.web.telegram.org"])
        await connection.close()

    async def test_real_websocket_requires_binary_protocol_and_relays_frames(self):
        self.helper._relay = HelperServer._relay.__get__(self.helper, HelperServer)

        async def echo(upstream):
            async for message in upstream:
                await upstream.send(message)

        upstream = await websockets.serve(
            echo, "127.0.0.1", 0, ssl=self.server_context,
            subprotocols=["binary"], origins=["https://web.telegram.org"],
            compression=None,
        )
        port = upstream.sockets[0].getsockname()[1]
        real_connect = websockets.connect
        trust = ssl.create_default_context(cafile=str(self.cert))
        trust.check_hostname = False

        def local_upstream(uri, **kwargs):
            kwargs["ssl"] = trust
            return real_connect(f"wss://127.0.0.1:{port}/apiws", **kwargs)

        connection = None
        try:
            with patch("helper_server.websockets.connect", side_effect=local_upstream):
                connection = await HelperConnection.connect_v2(
                    "127.0.0.1", self.port, self.fingerprint, "a" * 64,
                    "kws2.web.telegram.org",
                )
                frames = [b"first-frame", bytes(range(256)) * 128, b""]
                for frame in frames:
                    await connection.send(frame)
                    self.assertEqual(await asyncio.wait_for(connection.recv(), 2), frame)
        finally:
            if connection is not None:
                await connection.close()
            upstream.close()
            await upstream.wait_closed()

    async def test_transport_is_closed_even_after_recv_observes_eof(self):
        async def close_peer(reader, writer):
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(close_peer, "127.0.0.1", 0)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", server.sockets[0].getsockname()[1])
        connection = HelperConnection(reader, writer, "kws2.web.telegram.org", "127.0.0.1", 0)
        try:
            self.assertIsNone(await connection.recv())
            await connection.close()
            self.assertTrue(writer.is_closing())
        finally:
            writer.close()
            server.close()
            await server.wait_closed()

    async def test_download_only_stream_survives_idle_upload_and_quiet_reply_header(self):
        self.helper._relay = HelperServer._relay.__get__(self.helper, HelperServer)
        finished = asyncio.Event()

        async def download(upstream):
            # Each pause exceeds the shortened progress deadline. No upload is
            # sent at all, while complete download frames keep arriving.
            for index in range(4):
                await asyncio.sleep(0.06)
                await upstream.send(bytes([index]))
            await finished.wait()

        upstream = await websockets.serve(download, "127.0.0.1", 0, ssl=self.server_context,
            subprotocols=["binary"], origins=["https://web.telegram.org"], compression=None)
        port = upstream.sockets[0].getsockname()[1]
        real_connect = websockets.connect
        trust = ssl.create_default_context(cafile=str(self.cert))
        trust.check_hostname = False

        def local_upstream(uri, **kwargs):
            return real_connect(f"wss://127.0.0.1:{port}/apiws", ssl=trust, **kwargs)

        connection = None
        try:
            with patch("helper_server.websockets.connect", side_effect=local_upstream), \
                    patch("helper_server.FRAME_TIMEOUT", 0.025), patch("proxy.helper_conn.FRAME_TIMEOUT", 0.025):
                connection = await HelperConnection.connect_v2(
                    "127.0.0.1", self.port, self.fingerprint, "a" * 64, "kws2.web.telegram.org")
                for index in range(4):
                    self.assertEqual(await asyncio.wait_for(connection.recv(), 1), bytes([index]))
        finally:
            finished.set()
            if connection is not None:
                await connection.close()
            upstream.close()
            await upstream.wait_closed()

    async def test_started_data_header_and_body_still_have_progress_deadlines(self):
        for supplied in (b"\0", (3).to_bytes(4, "big") + b"x"):
            with self.subTest(supplied=supplied):
                reader = asyncio.StreamReader()
                reader.feed_data(supplied)
                with self.assertRaises(asyncio.TimeoutError):
                    await read_frame(reader, 0.02, allow_idle=True)
                reader = asyncio.StreamReader()
                reader.feed_data(supplied)
                connection = HelperConnection(reader, Mock(), "route", "localhost", 0)
                with self.assertRaises(asyncio.TimeoutError):
                    await connection._read_frame(0.02, allow_idle=True)

    async def test_authentication_header_keeps_strict_deadline_without_first_byte(self):
        with self.assertRaises(asyncio.TimeoutError):
            await read_frame(asyncio.StreamReader(), 0.02)
        connection = HelperConnection(asyncio.StreamReader(), Mock(), "route", "localhost", 0)
        with self.assertRaises(asyncio.TimeoutError):
            await connection._read_frame(0.02)

    async def test_data_progress_in_small_chunks_resets_stall_deadline(self):
        reader = asyncio.StreamReader()
        task = asyncio.create_task(read_frame(reader, 0.04, allow_idle=True))
        await asyncio.sleep(0.06)  # No first header byte yet: an allowed idle.
        reader.feed_data((4).to_bytes(4, "big"))
        for value in (b"a", b"b", b"c", b"d"):
            await asyncio.sleep(0.025)
            reader.feed_data(value)
        self.assertEqual(await asyncio.wait_for(task, 0.1), b"abcd")

    async def test_idle_data_wait_is_cancellable(self):
        task = asyncio.create_task(read_frame(asyncio.StreamReader(), 0.02, allow_idle=True))
        await asyncio.sleep(0.04)
        self.assertFalse(task.done())
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_wrong_token_is_rejected(self):
        with self.assertRaises(PermissionError):
            await HelperConnection.connect_v2(
                "127.0.0.1", self.port, self.fingerprint, "b" * 64,
                "kws2.web.telegram.org",
            )
        self.assertFalse(self.relay_domains)

    async def test_oversized_unauthenticated_token_is_rejected_without_body(self):
        trust = ssl.create_default_context(cafile=str(self.cert))
        trust.check_hostname = False
        reader, writer = await asyncio.open_connection(
            '127.0.0.1', self.port, ssl=trust)
        try:
            # No body follows: the old server waited for up to 16 MiB before
            # deciding that this unauthenticated token was invalid.
            writer.write((MAX_TOKEN_SIZE + 1).to_bytes(4, 'big'))
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
            self.assertFalse(self.relay_domains)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_oversized_route_is_rejected_without_body_after_authentication(self):
        trust = ssl.create_default_context(cafile=str(self.cert))
        trust.check_hostname = False
        reader, writer = await asyncio.open_connection(
            '127.0.0.1', self.port, ssl=trust)
        try:
            writer.write((64).to_bytes(4, 'big') + b'a' * 64
                         + (MAX_ROUTE_SIZE + 1).to_bytes(4, 'big'))
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
            self.assertFalse(self.relay_domains)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_listener_uses_small_buffer_before_authentication(self):
        args = SimpleNamespace(bind='127.0.0.1', secure_port=8444,
                               legacy_port=8443, allow_legacy=True)
        with patch('helper_server.asyncio.start_server', AsyncMock()) as start:
            await create_listener_servers(self.helper, args, self.server_context)
        self.assertEqual(start.await_count, 2)
        self.assertEqual([call.kwargs['limit'] for call in start.await_args_list],
                         [STREAM_BUFFER_LIMIT] * 2)
        self.assertLessEqual(STREAM_BUFFER_LIMIT, 65536)

    async def test_failed_legacy_bind_rolls_back_tls_listener(self):
        occupied = await asyncio.start_server(lambda r, w: w.close(), '127.0.0.1', 0)
        args = SimpleNamespace(bind='127.0.0.1', secure_port=0,
                               legacy_port=occupied.sockets[0].getsockname()[1], allow_legacy=True)
        real_start = asyncio.start_server
        created, ports = [], []

        async def tracked_start(*positional, **kwargs):
            server = await real_start(*positional, **kwargs)
            created.append(server)
            ports.append(server.sockets[0].getsockname()[1])
            return server

        try:
            with patch('helper_server.asyncio.start_server', tracked_start):
                with self.assertRaises(OSError):
                    await create_listener_servers(self.helper, args, self.server_context)
            self.assertEqual(len(created), 1)
            self.assertFalse(created[0].is_serving())
            self.assertFalse(created[0].sockets)
            # Actual bind proves the first listener no longer owns its port.
            rebound = await real_start(lambda r, w: w.close(), '127.0.0.1', ports[0])
            rebound.close()
            await rebound.wait_closed()
        finally:
            occupied.close()
            for server in created:
                server.close()
            await asyncio.gather(occupied.wait_closed(), *(s.wait_closed() for s in created))

    async def test_cancelled_second_listener_creation_rolls_back_first(self):
        first = Mock(close=Mock(), wait_closed=AsyncMock())
        entered = asyncio.Event()

        async def start(*args, **kwargs):
            if args[2] == 8444:
                return first
            entered.set()
            await asyncio.Future()

        args = SimpleNamespace(bind='127.0.0.1', secure_port=8444,
                               legacy_port=8443, allow_legacy=True)
        with patch('helper_server.asyncio.start_server', start):
            task = asyncio.create_task(create_listener_servers(self.helper, args, self.server_context))
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        first.close.assert_called_once()
        first.wait_closed.assert_awaited_once()

    async def test_stalled_tls_close_keeps_slot_until_bounded_abort(self):
        reader = asyncio.StreamReader()
        reader.feed_data((MAX_TOKEN_SIZE + 1).to_bytes(4, 'big'))
        closing = asyncio.Event()

        async def stalled_close():
            closing.set()
            await asyncio.Future()

        writer = Mock(wait_closed=AsyncMock(side_effect=stalled_close))
        writer.get_extra_info.return_value = ('192.0.2.1', 12345)
        helper = HelperServer('a' * 64)
        with patch('helper_server.CLOSE_TIMEOUT', 0.05):
            task = asyncio.create_task(helper.handle(reader, writer, secure=True))
            await asyncio.wait_for(closing.wait(), 1)
            self.assertEqual(helper._active, 1)
            self.assertIn(writer, helper._writers)
            await asyncio.wait_for(task, 1)
        self.assertEqual(helper._active, 0)
        self.assertFalse(helper._writers)
        writer.transport.abort.assert_called_once()

    async def test_rejected_client_does_not_wait_for_tls_shutdown(self):
        helper = HelperServer('a' * 64)
        helper._active = MAX_CONNECTIONS
        writer = Mock(wait_closed=AsyncMock())
        writer.get_extra_info.return_value = ('192.0.2.1', 12345)
        await helper.handle(asyncio.StreamReader(), writer, secure=True)
        writer.wait_closed.assert_not_awaited()
        writer.transport.abort.assert_called_once()

    async def test_wrong_route_is_rejected(self):
        with self.assertRaises(PermissionError):
            await HelperConnection.connect_v2(
                "127.0.0.1", self.port, self.fingerprint, "a" * 64,
                "zws2-1.web.telegram.org",
            )
        self.assertFalse(self.relay_domains)

    async def test_wrong_fingerprint_fails_before_authentication_and_no_downgrade(self):
        with self.assertRaises(ssl.SSLError):
            await HelperConnection.connect_v2(
                "127.0.0.1", self.port, "0" * 64, "a" * 64,
                "kws2.web.telegram.org",
            )
        self.assertFalse(self.relay_domains)

    async def test_route_catalog_comes_from_upstream_ws_routes(self):
        self.assertIn("kws2.web.telegram.org", route_catalog())
        self.assertIn("kws4-1.web.telegram.org", route_catalog())
        self.assertNotIn("attacker.example", route_catalog())
        self.assertNotIn("zws2-1.web.telegram.org", route_catalog())

    async def test_frame_over_16_mib_is_rejected(self):
        reader = asyncio.StreamReader()
        reader.feed_data((MAX_FRAME_SIZE + 1).to_bytes(4, "big"))
        with self.assertRaisesRegex(ValueError, "frame_too_large"):
            await read_frame(reader)

    async def test_connection_limits_are_enforced_per_ip_and_globally(self):
        helper = HelperServer("x" * 64)
        self.assertTrue(all(helper._admit("192.0.2.1")
                            for _ in range(MAX_CONNECTIONS_PER_IP)))
        self.assertFalse(helper._admit("192.0.2.1"))
        for _ in range(MAX_CONNECTIONS_PER_IP):
            helper._release("192.0.2.1")
        self.assertTrue(all(helper._admit(str(ipaddress.ip_address(i + 1)))
                            for i in range(MAX_CONNECTIONS)))
        self.assertFalse(helper._admit("198.51.100.1"))

    async def test_legacy_listener_is_opt_in(self):
        def unused_port():
            sock = __import__("socket").socket()
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            sock.close()
            return port

        secure_port, legacy_port = unused_port(), unused_port()
        while legacy_port == secure_port:
            legacy_port = unused_port()
        args = SimpleNamespace(bind="127.0.0.1", secure_port=secure_port,
                               legacy_port=legacy_port, allow_legacy=False)
        servers = await create_listener_servers(self.helper, args, self.server_context)
        self.assertEqual(len(servers), 1)
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))

        args.allow_legacy = True
        servers = await create_listener_servers(self.helper, args, self.server_context)
        self.assertEqual(len(servers), 2)
        actual_legacy_port = servers[1].sockets[0].getsockname()[1]
        legacy = await HelperConnection.connect_legacy(
            "127.0.0.1", actual_legacy_port, "zws2-1.web.telegram.org")
        await asyncio.wait_for(self.relay_started.wait(), 1)
        self.assertEqual(self.relay_domains, ["zws2-1.web.telegram.org"])
        await legacy.close()
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))


if __name__ == "__main__":
    unittest.main()
