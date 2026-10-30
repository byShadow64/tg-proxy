import asyncio
import os
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
import time
from types import SimpleNamespace
from unittest.mock import patch

import websockets
from websockets.asyncio.server import ServerConnection
from websockets.frames import Frame, OP_BINARY, OP_CONT
from websockets.exceptions import ConnectionClosed, ConnectionClosedError

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from helper_registry import RegistryService, RegistryStore
from helper_registry_agent import RegistryTransport, refresh_configuration, write_configuration
from helper_server import HelperServer, write_frame
from proxy.helper_conn import HelperConnection
from proxy.registry_helper import MAX_REGISTERED_MESSAGE_SIZE, MIN_REGISTERED_MESSAGE_COST, RegistryLeaseAuthorizer
from proxy import registry_protocol as p
from tests.test_helper_protocol import _make_certificate


class RegistryAgentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "private"
        self.directory.mkdir(mode=0o700)
        self.registry = ec.generate_private_key(ec.SECP256R1())
        self.agent = ec.generate_private_key(ec.SECP256R1())
        self.device = ec.generate_private_key(ec.SECP256R1())
        self.public = self.directory / "registry-public.pem"
        self.public.write_bytes(self.registry.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.store = RegistryStore(self.directory / "registry.sqlite3")
        self.helper = self.store.provision_helper("192.0.2.10", 8444, "ab" * 32, self.agent.public_key())
        self.now = 1000
        self.service = RegistryService(self.store, self.registry, clock=lambda: self.now)
        self.output = self.directory / "registry-config.json"
        service = self.service
        class LocalTransport:
            def request(self, path, value):
                return service.dispatch(path, p.json_bytes(value))
        self.transport = LocalTransport()

    def tearDown(self):
        self.temp.cleanup()

    def refresh(self, **overrides):
        arguments = dict(transport=self.transport, private_key=self.agent, registry_key=self.registry.public_key(),
                         helper_id=self.helper, fingerprint="ab" * 32, output=self.output, now=self.now)
        return refresh_configuration(**(arguments | overrides))

    def test_agent_proves_registered_key_and_writes_verified_configuration(self):
        config = self.refresh()
        self.assertEqual(self.helper, config["helper_id"])
        self.assertEqual(32, config["max_device_connections"])
        self.assertNotIn("token", config)
        stored = p.parse_json(self.output.read_bytes())
        self.assertEqual(config, p.verify_helper_config(stored, self.registry.public_key(), now=1000))
        if os.name != "nt":
            self.assertEqual(0o600, self.output.stat().st_mode & 0o777)

    def test_wrong_central_key_or_certificate_never_replaces_old_config(self):
        self.refresh()
        original = self.output.read_bytes()
        other = ec.generate_private_key(ec.SECP256R1())
        for overrides in ({"registry_key": other.public_key()}, {"fingerprint": "cd" * 32}, {"private_key": self.device}):
            with self.assertRaises(p.RegistryError):
                self.refresh(**overrides)
            self.assertEqual(original, self.output.read_bytes())

    def test_per_device_quota_spans_multiple_leases_and_releases(self):
        self.refresh()
        authorizer = RegistryLeaseAuthorizer(self.public, self.output, bytes.fromhex("ab" * 32), port=8444, clock=lambda: self.now)
        did = p.device_id(self.device.public_key())
        tokens = [p.issue_lease(self.registry, self.helper, did, "ab" * 32, now=1000).encode("ascii") for _ in range(2)]
        for _ in range(32):
            self.assertEqual(did, authorizer.acquire(tokens[0]))
        with self.assertRaisesRegex(p.RegistryError, "quota"):
            authorizer.acquire(tokens[1])
        authorizer.release(did)
        authorizer.acquire(tokens[1])
        for _ in range(32):
            authorizer.release(did)
        self.assertEqual({}, authorizer._counts)

    def test_stale_disabled_wrong_pin_and_wrong_port_fail_closed(self):
        self.refresh()
        did = p.device_id(self.device.public_key())
        token = p.issue_lease(self.registry, self.helper, did, "ab" * 32, now=1000).encode()
        authorizer = RegistryLeaseAuthorizer(self.public, self.output, bytes.fromhex("ab" * 32), port=8444, clock=lambda: self.now)
        self.now = 1600
        with self.assertRaises(p.RegistryError):
            authorizer.acquire(token)
        self.now = 1000
        wrong = RegistryLeaseAuthorizer(self.public, self.output, bytes.fromhex("cd" * 32), clock=lambda: self.now)
        with self.assertRaises(p.RegistryError):
            wrong.acquire(token)
        wrong = RegistryLeaseAuthorizer(self.public, self.output, bytes.fromhex("ab" * 32), port=8445, clock=lambda: self.now)
        with self.assertRaises(p.RegistryError):
            wrong.acquire(token)
        self.store.provision_helper("192.0.2.10", 8444, "ab" * 32, self.agent.public_key(), enabled=False)
        self.refresh()
        with self.assertRaisesRegex(p.RegistryError, "denied"):
            authorizer.acquire(token)

    def test_transport_requires_https_and_honors_cancellation_without_network(self):
        for url in ("http://192.0.2.10", "https://user:secret@192.0.2.10", "https://192.0.2.10/?token=x", "https://192.0.2.10/#x"):
            with self.assertRaises(p.RegistryError):
                RegistryTransport(url)
        cancelled = threading.Event()
        cancelled.set()
        transport = RegistryTransport("https://192.0.2.10", cancelled=cancelled)
        with self.assertRaisesRegex(p.RegistryError, "cancelled"):
            transport.request("/v1/challenge", dict(v=1))


class RegistryHelperTLSIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        directory = Path(self.temp.name)
        self.cert, self.key, self.pin = _make_certificate(directory)
        private = directory / "private"
        private.mkdir(mode=0o700)
        self.registry = ec.generate_private_key(ec.SECP256R1())
        self.device = ec.generate_private_key(ec.SECP256R1())
        self.helper_id = p.b64encode(b"h" * 16)
        public = private / "public.pem"
        public.write_bytes(self.registry.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.config_path = private / "registry.json"
        config = dict(v=1, helper_id=self.helper_id, ip="192.0.2.10", port=8444, fingerprint=self.pin,
                      iat=1000, exp=1600, enabled=True, max_device_connections=32, access=p.ACCESS)
        write_configuration(self.config_path, p.sign_envelope(config, self.registry, context=p.CONFIG_CONTEXT))
        self.now = 1000
        self.authorizer = RegistryLeaseAuthorizer(public, self.config_path, bytes.fromhex(self.pin), clock=lambda: self.now)
        self.helper = HelperServer("a" * 64, registry_authorizer=self.authorizer)
        self.relay_calls = 0
        async def relay(reader, writer, domain, *, secure=False, registry_device=None):
            self.relay_calls += 1
            await write_frame(writer, b"OK", 1)
            await reader.read()
        self.helper._relay = relay
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server = await asyncio.start_server(lambda r, w: self.helper.handle(r, w, secure=True), "127.0.0.1", 0, ssl=context)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        await self.helper.close_clients()
        self.temp.cleanup()

    async def test_signed_lease_auth_uses_existing_v2_and_releases_on_close(self):
        did = p.device_id(self.device.public_key())
        token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000)
        connection = await HelperConnection.connect_v2("127.0.0.1", self.port, self.pin, token, "kws2.web.telegram.org")
        self.assertEqual(1, self.authorizer._counts[did])
        await connection.close()
        for _ in range(100):
            if not self.authorizer._counts:
                break
            await asyncio.sleep(0.01)
        self.assertEqual({}, self.authorizer._counts)
        self.assertEqual(1, self.relay_calls)

    async def test_expired_control_plane_rejects_lease_but_preserves_private_global_token(self):
        self.now = 1700
        token = p.issue_lease(self.registry, self.helper_id, p.device_id(self.device.public_key()), self.pin, now=1700)
        with self.assertRaises(PermissionError):
            await HelperConnection.connect_v2("127.0.0.1", self.port, self.pin, token, "kws2.web.telegram.org")
        connection = await HelperConnection.connect_v2("127.0.0.1", self.port, self.pin, "a" * 64, "kws2.web.telegram.org")
        await connection.close()
        self.assertEqual(1, self.relay_calls)

    async def test_foreign_helper_lease_and_non_catalog_route_are_rejected(self):
        did = p.device_id(self.device.public_key())
        token = p.issue_lease(self.registry, p.b64encode(b"x" * 16), did, self.pin, now=1000)
        with self.assertRaises(PermissionError):
            await HelperConnection.connect_v2("127.0.0.1", self.port, self.pin, token, "kws2.web.telegram.org")
        token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000)
        with self.assertRaises(PermissionError):
            await HelperConnection.connect_v2("127.0.0.1", self.port, self.pin, token, "attacker.invalid")
        await asyncio.sleep(0.01)
        self.assertEqual({}, self.authorizer._counts)
        self.assertEqual(0, self.relay_calls)

    async def test_registered_large_frame_is_rejected_before_reading_body(self):
        from helper_server import MAX_REGISTERED_FRAME_SIZE, HEADER, read_frame
        did = p.device_id(self.device.public_key())
        token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000)
        self.helper._relay = HelperServer._relay.__get__(self.helper, HelperServer)
        # A local upstream accepts the route, but no giant client body is sent.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        async def echo(upstream):
            async for message in upstream:
                await upstream.send(message)
        server = await websockets.serve(echo, "127.0.0.1", 0, ssl=context, subprotocols=["binary"], compression=None)
        real_connect = websockets.connect
        trust = ssl.create_default_context(cafile=str(self.cert))
        trust.check_hostname = False
        options = []
        def connect(uri, **kwargs):
            options.append(kwargs.copy())
            kwargs["ssl"] = trust
            return real_connect("wss://127.0.0.1:" + str(server.sockets[0].getsockname()[1]) + "/apiws", **kwargs)
        try:
            with patch("helper_server.websockets.connect", side_effect=connect):
                connection = await HelperConnection.connect_v2("127.0.0.1", self.port, self.pin, token, "kws2.web.telegram.org")
                connection.writer.write(HEADER.pack(MAX_REGISTERED_FRAME_SIZE + 1))
                await connection.writer.drain()
                self.assertEqual(b"", await asyncio.wait_for(connection.reader.read(), 2))
                await connection.close()
            self.assertEqual(MAX_REGISTERED_FRAME_SIZE, options[0]["max_size"])
            self.assertEqual(1, options[0]["max_queue"])
        finally:
            server.close()
            await server.wait_closed()

    async def test_registered_download_chunks_reassemble_without_changing_stream(self):
        self.helper._relay = HelperServer._relay.__get__(self.helper, HelperServer)
        did = p.device_id(self.device.public_key())
        token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        async def echo(upstream):
            async for message in upstream:
                await upstream.send(message)
        server = await websockets.serve(echo, "127.0.0.1", 0, ssl=context, subprotocols=["binary"], compression=None)
        real_connect = websockets.connect
        trust = ssl.create_default_context(cafile=str(self.cert))
        trust.check_hostname = False
        def connect(uri, **kwargs):
            kwargs["ssl"] = trust
            return real_connect("wss://127.0.0.1:" + str(server.sockets[0].getsockname()[1]) + "/apiws", **kwargs)
        try:
            with patch("helper_server.websockets.connect", side_effect=connect):
                connection = await HelperConnection.connect_v2("127.0.0.1", self.port, self.pin, token, "kws2.web.telegram.org")
                payload = bytes(range(256)) * 2048
                await connection.send(payload)
                received = bytearray()
                while len(received) < len(payload):
                    chunk = await asyncio.wait_for(connection.recv(), 3)
                    self.assertLessEqual(len(chunk), 65536)
                    received.extend(chunk)
                self.assertEqual(payload, bytes(received))
                await connection.close()
        finally:
            server.close()
            await server.wait_closed()

    async def test_private_and_registered_upload_single_binary_fin_to_strict_upstream(self):
        self.helper._relay = HelperServer._relay.__get__(self.helper, HelperServer)
        token = p.issue_lease(self.registry, self.helper_id, p.device_id(self.device.public_key()), self.pin, now=1000)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        captured = []
        class StrictBinary(ServerConnection):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.wire = []
                captured.append(self.wire)
            def process_event(self, event):
                if isinstance(event, Frame) and event.opcode in {OP_BINARY, OP_CONT}:
                    self.wire.append((event.opcode, event.fin, len(event.data)))
                    if event.opcode == OP_CONT or not event.fin:
                        self.protocol.fail(1002, 'single binary frame required')
                        self.send_data()
                        return
                super().process_event(event)
        async def echo(upstream):
            try:
                async for message in upstream:
                    await upstream.send(message)
            except ConnectionClosed:
                pass
        server = await websockets.serve(echo, '127.0.0.1', 0, ssl=context, subprotocols=['binary'],
                                        compression=None, max_size=MAX_REGISTERED_MESSAGE_SIZE,
                                        create_connection=StrictBinary)
        real_connect = websockets.connect
        trust = ssl.create_default_context(cafile=str(self.cert))
        trust.check_hostname = False
        url = 'wss://127.0.0.1:' + str(server.sockets[0].getsockname()[1]) + '/apiws'
        def connect(uri, **kwargs):
            kwargs['ssl'] = trust
            return real_connect(url, **kwargs)
        payloads = [bytes(range(64)), b'm' * 65536, b'x' * MAX_REGISTERED_MESSAGE_SIZE]
        try:
            with patch('helper_server.websockets.connect', side_effect=connect):
                for credential in ('a' * 64, token):
                    connection = await HelperConnection.connect_v2('127.0.0.1', self.port, self.pin, credential, 'kws2.web.telegram.org')
                    try:
                        for payload in payloads:
                            await connection.send(payload)
                            received = bytearray()
                            while len(received) < len(payload):
                                part = await asyncio.wait_for(connection.recv(), 4)
                                self.assertIsNotNone(part)
                                received.extend(part)
                            self.assertEqual(payload, bytes(received))
                    finally:
                        await connection.close()
            expected = [(OP_BINARY, True, len(payload)) for payload in payloads]
            self.assertEqual([expected, expected], captured)
            # Prove this fixture would reject the old send(async_iterator) path,
            # even when its only payload is the 64-byte initialization message.
            async with real_connect(url, ssl=trust, proxy=None, subprotocols=['binary'], compression=None) as upstream:
                async def fragmented():
                    yield payloads[0]
                await upstream.send(fragmented())
                with self.assertRaises(ConnectionClosedError):
                    await upstream.recv()
            self.assertFalse(captured[2][0][1])
        finally:
            server.close()
            await server.wait_closed()

    async def test_upstream_pump_failure_logs_type_without_remote_reason(self):
        self.helper._relay = HelperServer._relay.__get__(self.helper, HelperServer)
        token = p.issue_lease(self.registry, self.helper_id, p.device_id(self.device.public_key()), self.pin, now=1000)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        async def reject(upstream):
            await upstream.recv()
            await upstream.close(code=1008, reason='synthetic-secret-must-not-be-logged')
        server = await websockets.serve(reject, '127.0.0.1', 0, ssl=context, subprotocols=['binary'], compression=None)
        real_connect = websockets.connect
        trust = ssl.create_default_context(cafile=str(self.cert))
        trust.check_hostname = False
        def connect(uri, **kwargs):
            kwargs['ssl'] = trust
            return real_connect('wss://127.0.0.1:' + str(server.sockets[0].getsockname()[1]) + '/apiws', **kwargs)
        try:
            with self.assertLogs('tg-helper', level='WARNING') as logged, patch('helper_server.websockets.connect', side_effect=connect):
                connection = await HelperConnection.connect_v2('127.0.0.1', self.port, self.pin, token, 'kws2.web.telegram.org')
                await connection.send(b'x' * 64)
                self.assertIsNone(await asyncio.wait_for(connection.recv(), 3))
                await connection.close()
            self.assertIn('ConnectionClosedError', '\n'.join(logged.output))
            self.assertNotIn('synthetic-secret', '\n'.join(logged.output))
        finally:
            server.close()
            await server.wait_closed()

    async def test_empty_registered_upload_is_rejected_before_forward_private_unchanged(self):
        self.helper._relay = HelperServer._relay.__get__(self.helper, HelperServer)
        token = p.issue_lease(self.registry, self.helper_id, p.device_id(self.device.public_key()), self.pin, now=1000)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        messages = []
        async def echo(upstream):
            captured = []
            messages.append(captured)
            async for message in upstream:
                captured.append(message)
                await upstream.send(message)
        server = await websockets.serve(echo, '127.0.0.1', 0, ssl=context, subprotocols=['binary'], compression=None)
        real_connect = websockets.connect
        trust = ssl.create_default_context(cafile=str(self.cert))
        trust.check_hostname = False
        def connect(uri, **kwargs):
            kwargs['ssl'] = trust
            return real_connect('wss://127.0.0.1:' + str(server.sockets[0].getsockname()[1]) + '/apiws', **kwargs)
        try:
            with patch('helper_server.websockets.connect', side_effect=connect):
                for credential, expected in (('a' * 64, b''), (token, None)):
                    connection = await HelperConnection.connect_v2('127.0.0.1', self.port, self.pin, credential, 'kws2.web.telegram.org')
                    await connection.send(b'')
                    self.assertEqual(expected, await asyncio.wait_for(connection.recv(), 3))
                    await connection.close()
            self.assertEqual([[b''], []], messages)
        finally:
            server.close()
            await server.wait_closed()

    async def test_bandwidth_bucket_is_shared_across_keys_and_wait_is_cancellable(self):
        from proxy.registry_helper import RegistryLeaseAuthorizer
        # The existing authorizer has a valid config and fixed root trust.
        self.authorizer.device_rate = self.authorizer.shared_rate = 65536
        self.authorizer._shared_bucket = [MAX_REGISTERED_MESSAGE_SIZE, time.monotonic()]
        ids = []
        for key in (self.device, ec.generate_private_key(ec.SECP256R1())):
            did = p.device_id(key.public_key())
            token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000)
            ids.append(self.authorizer.acquire(token.encode()))
        await self.authorizer.throttle(ids[0], MAX_REGISTERED_MESSAGE_SIZE)
        waiting = asyncio.create_task(self.authorizer.throttle(ids[1], 65536))
        await asyncio.sleep(0.04)
        self.assertFalse(waiting.done())  # A new key does not reset the aggregate bucket.
        self.assertEqual(MAX_REGISTERED_MESSAGE_SIZE, self.authorizer._buckets[ids[1]][0])
        waiting.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiting
        for identifier in ids:
            self.authorizer.release(identifier)
        self.assertEqual({}, self.authorizer._counts)
        self.assertLessEqual(len(self.authorizer._buckets), 256)
        self.authorizer._prune_buckets(time.monotonic() + 33)
        self.assertEqual({}, self.authorizer._buckets)

    async def test_reconnecting_same_device_does_not_reset_its_bandwidth_burst(self):
        self.authorizer.device_rate = 65536
        did = p.device_id(self.device.public_key())
        token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000).encode()
        self.authorizer.acquire(token)
        await self.authorizer.throttle(did, MAX_REGISTERED_MESSAGE_SIZE)
        self.authorizer.release(did)
        self.authorizer.acquire(token)
        self.assertLess(self.authorizer._buckets[did][0], 32768)
        waiting = asyncio.create_task(self.authorizer.throttle(did, 65536))
        await asyncio.sleep(0.03)
        self.assertFalse(waiting.done())
        waiting.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiting
        self.authorizer.release(did)

    async def test_full_message_quota_is_bounded_and_recovers_at_new_refill_interval(self):
        self.authorizer.device_rate = 65536
        did = p.device_id(self.device.public_key())
        token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000).encode()
        self.authorizer.acquire(token)
        await asyncio.wait_for(self.authorizer.throttle(did, MAX_REGISTERED_MESSAGE_SIZE), 1)
        with self.assertRaisesRegex(p.RegistryError, 'invalid_data'):
            await self.authorizer.throttle(did, MAX_REGISTERED_MESSAGE_SIZE + 1)
        self.authorizer.release(did)
        now = time.monotonic()
        self.assertGreaterEqual(self.authorizer._closed_until[did] - now, 31.9)
        self.authorizer._prune_buckets(now + 31)
        self.assertIn(did, self.authorizer._buckets)
        self.authorizer._prune_buckets(now + 33)
        self.assertNotIn(did, self.authorizer._buckets)
        self.authorizer.acquire(token)
        self.assertEqual(MAX_REGISTERED_MESSAGE_SIZE, self.authorizer._buckets[did][0])
        self.authorizer.release(did)

    async def test_whole_message_fifo_progress_under_competing_small_admissions(self):
        for empty_bucket in ('device', 'shared'):
            with self.subTest(empty_bucket=empty_bucket):
                clock = [0.0]
                self.authorizer.device_rate = self.authorizer.shared_rate = 65536
                ids = []
                for key in (self.device, ec.generate_private_key(ec.SECP256R1())):
                    did = p.device_id(key.public_key())
                    token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000).encode()
                    ids.append(self.authorizer.acquire(token))
                    self.authorizer._buckets[did] = [MAX_REGISTERED_MESSAGE_SIZE, 0]
                self.authorizer._shared_bucket = [MAX_REGISTERED_MESSAGE_SIZE, 0]
                if empty_bucket == 'device':
                    self.authorizer._buckets[ids[0]][0] = 0
                else:
                    self.authorizer._shared_bucket[0] = 0
                order = []
                async def charge(label, identifier, amount):
                    await self.authorizer.throttle(identifier, amount)
                    order.append(label)
                async def yield_tick(delay):
                    await asyncio.sleep(0)
                with patch('proxy.registry_helper.time', SimpleNamespace(monotonic=lambda: clock[0])), patch(
                        'proxy.registry_helper.asyncio', SimpleNamespace(sleep=yield_tick)):
                    large = asyncio.create_task(charge('large', ids[0], MAX_REGISTERED_MESSAGE_SIZE))
                    await asyncio.sleep(0)
                    small = asyncio.create_task(charge('small', ids[0] if empty_bucket == 'device' else ids[1], 65536))
                    for tick in range(1, 32):
                        clock[0] = tick
                        await asyncio.sleep(0)
                        self.assertFalse(small.done())
                    self.assertFalse(large.done())
                    clock[0] = 32
                    for _ in range(3):
                        await asyncio.sleep(0)
                    self.assertEqual(['large'], order)
                    clock[0] = 33
                    await asyncio.wait_for(asyncio.gather(large, small), 1)
                    self.assertEqual(['large', 'small'], order)
                for did in ids:
                    self.authorizer.release(did)
                self.assertFalse(self.authorizer._waiters)

    async def test_cancelling_fifo_head_releases_next_without_losing_credit(self):
        ids = []
        for key in (self.device, ec.generate_private_key(ec.SECP256R1())):
            did = p.device_id(key.public_key())
            token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000).encode()
            ids.append(self.authorizer.acquire(token))
            self.authorizer._buckets[did] = [MAX_REGISTERED_MESSAGE_SIZE, 0]
        self.authorizer._buckets[ids[0]][0] = 0
        self.authorizer._shared_bucket = [MAX_REGISTERED_MESSAGE_SIZE, 0]
        async def yield_tick(delay):
            await asyncio.sleep(0)
        with patch('proxy.registry_helper.time', SimpleNamespace(monotonic=lambda: 0)), patch(
                'proxy.registry_helper.asyncio', SimpleNamespace(sleep=yield_tick)):
            large = asyncio.create_task(self.authorizer.throttle(ids[0], MAX_REGISTERED_MESSAGE_SIZE))
            await asyncio.sleep(0)
            small = asyncio.create_task(self.authorizer.throttle(ids[1], 65536))
            await asyncio.sleep(0)
            self.assertFalse(small.done())
            large.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await large
            await asyncio.wait_for(small, 1)
            self.assertEqual(MAX_REGISTERED_MESSAGE_SIZE - 65536, self.authorizer._shared_bucket[0])
            self.assertEqual(0, self.authorizer._buckets[ids[0]][0])
            self.assertFalse(self.authorizer._waiters)
        for did in ids:
            self.authorizer.release(did)

    async def test_fifo_waiter_count_is_bounded_and_cancel_removes_entries(self):
        did = p.device_id(self.device.public_key())
        token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000).encode()
        self.authorizer.acquire(token)
        self.authorizer.max_registered_connections = 1
        self.authorizer._buckets[did] = [0, time.monotonic()]
        waiting = [asyncio.create_task(self.authorizer.throttle(did, MAX_REGISTERED_MESSAGE_SIZE)) for _ in range(2)]
        await asyncio.sleep(0)
        with self.assertRaisesRegex(p.RegistryError, 'quota'):
            await self.authorizer.throttle(did, 1)
        self.assertEqual(2, len(self.authorizer._waiters))
        for task in waiting:
            task.cancel()
        await asyncio.gather(*waiting, return_exceptions=True)
        self.assertFalse(self.authorizer._waiters)
        self.authorizer.release(did)

    async def test_tiny_messages_bill_minimum_across_devices_cancel_and_reconnect(self):
        keys = [self.device, ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())]
        ids, tokens = [], []
        for key in keys:
            did = p.device_id(key.public_key())
            token = p.issue_lease(self.registry, self.helper_id, did, self.pin, now=1000).encode()
            ids.append(self.authorizer.acquire(token))
            tokens.append(token)
            self.authorizer._buckets[did] = [MAX_REGISTERED_MESSAGE_SIZE, 0]
        self.authorizer._shared_bucket = [4 * 1024 * 1024, 0]
        clock = [0.0]
        async def yield_tick(delay):
            await asyncio.sleep(0)
        with patch('proxy.registry_helper.time', SimpleNamespace(monotonic=lambda: clock[0])), patch(
                'proxy.registry_helper.asyncio', SimpleNamespace(sleep=yield_tick)):
            await self.authorizer.throttle_message(ids[0], 1)
            self.assertEqual(MAX_REGISTERED_MESSAGE_SIZE - MIN_REGISTERED_MESSAGE_COST, self.authorizer._buckets[ids[0]][0])
            for _ in range(511):
                await self.authorizer.throttle_message(ids[0], 64)
            self.assertEqual(0, self.authorizer._buckets[ids[0]][0])
            self.authorizer.release(ids[0])
            self.authorizer.acquire(tokens[0])
            blocked = asyncio.create_task(self.authorizer.throttle_message(ids[0], 1))
            await asyncio.sleep(0)
            self.assertFalse(blocked.done())
            blocked.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await blocked
            self.assertEqual(0, self.authorizer._buckets[ids[0]][0])
            for _ in range(512):
                await self.authorizer.throttle_message(ids[1], 1)
            self.assertEqual(0, self.authorizer._shared_bucket[0])
            blocked = asyncio.create_task(self.authorizer.throttle_message(ids[2], 1))
            await asyncio.sleep(0)
            self.assertFalse(blocked.done())
            blocked.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await blocked
            self.assertEqual(MAX_REGISTERED_MESSAGE_SIZE, self.authorizer._buckets[ids[2]][0])
            self.assertEqual(0, self.authorizer._shared_bucket[0])
            self.assertFalse(self.authorizer._waiters)
        for did in ids:
            self.authorizer.release(did)
