"""Cancellation at completed I/O must still stop its owning H2 operation."""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from h2.config import H2Configuration
from h2.connection import H2Connection

from proxy.h2_transport import H2Transport, _Connection, _ResponseStream


class _Readiness(asyncio.Event):
    """Complete a dependency and request its owner's stop in the same turn."""

    def __init__(self, ready=lambda: None):
        super().__init__()
        self.owner = None
        self.ready = ready

    async def wait(self):
        self.ready()
        self.set()
        loop = asyncio.get_running_loop()
        completed = loop.create_future()
        loop.call_soon(completed.set_result, True)
        loop.call_soon(self.owner.cancel, 'owned H2 operation stopped')
        return await completed


class _Writer:
    def __init__(self):
        self.closed = False
        self.writes = []
        self.drain_boundary = None
        self.close_boundary = None

    def write(self, value):
        self.writes.append(value)

    async def drain(self):
        if self.drain_boundary is not None:
            await self.drain_boundary.wait()

    def close(self):
        self.closed = True

    async def wait_closed(self):
        if self.close_boundary is not None:
            await self.close_boundary.wait()

    def get_extra_info(self, name):
        if name == 'ssl_object':
            return SimpleNamespace(selected_alpn_protocol=lambda: 'h2')
        return None


class H2TimeoutCancellationTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.owned = []
        self.connections = []
        self.transports = []

    async def asyncTearDown(self):
        for task in self.owned:
            if not task.done():
                task.cancel()
        if self.owned:
            _, pending = await asyncio.wait(self.owned, timeout=1)
            self.assertFalse(pending, 'owned operation did not stop during cleanup')
            await asyncio.gather(*self.owned, return_exceptions=True)
        for connection in self.connections:
            connection.writer.drain_boundary = None
            connection.writer.close_boundary = None
            await connection.aclose()
            for stream in list(connection.streams.values()):
                await stream.aclose()
            self.assertTrue(connection.writer.closed)
            self.assertTrue(connection.reader_task.done())
            self.assertFalse(connection.streams)
            self.assertFalse(connection.write_lock.locked())
        for transport in self.transports:
            await transport.aclose()
            self.assertFalse(transport.connect_lock.locked())

    def connection(self, *, write_timeout=0.02, reader=None, writer=None):
        connection = _Connection(reader or asyncio.StreamReader(), writer or _Writer(),
                                 64, write_timeout)
        self.connections.append(connection)
        return connection

    async def assert_stopped(self, operation, boundary):
        task = asyncio.create_task(operation)
        self.owned.append(task)
        boundary.owner = task
        done, _ = await asyncio.wait({task}, timeout=1)
        self.assertIn(task, done, 'operation continued after its stop request')
        self.assertTrue(task.cancelled(), 'operation swallowed its accepted cancellation')

    def stream(self, connection):
        connection.h2.send_headers(1, [(b':method', b'POST'), (b':scheme', b'https'),
                                       (b':authority', b'example.invalid'), (b':path', b'/')])
        stream = _ResponseStream(connection, 1, 0.02)
        connection.streams[1] = stream
        return stream

    async def test_response_readiness_does_not_swallow_stop(self):
        connection = self.connection()
        stream = self.stream(connection)
        stream.changed = _Readiness()
        await self.assert_stopped(stream.wait(), stream.changed)

    async def test_stream_capacity_readiness_does_not_swallow_stop(self):
        connection = self.connection()
        connection.changed = _Readiness(lambda: setattr(connection, 'settings_received', True))
        await self.assert_stopped(connection.reserve({'pool': 0.5, 'read': 0.02}),
                                  connection.changed)

    async def test_upload_window_readiness_does_not_swallow_stop(self):
        connection = self.connection()
        stream = self.stream(connection)
        connection.h2.outbound_flow_control_window = 0
        connection.changed = _Readiness(
            lambda: setattr(connection.h2, 'outbound_flow_control_window', 65535))
        request = httpx.Request('POST', 'https://example.invalid/', content=b'payload')
        await self.assert_stopped(connection.send_body(request, stream), connection.changed)

    async def test_socket_drain_readiness_does_not_swallow_stop(self):
        connection = self.connection()
        boundary = connection.writer.drain_boundary = _Readiness()
        await self.assert_stopped(connection.drain(), boundary)
        self.assertFalse(connection.write_lock.locked())

    async def test_socket_close_readiness_does_not_swallow_stop(self):
        connection = self.connection()
        boundary = connection.writer.close_boundary = _Readiness()
        await self.assert_stopped(connection.aclose(), boundary)

    async def test_tls_connection_readiness_does_not_swallow_stop(self):
        # A real H2 response is supplied in memory; no socket or external host is opened.
        client = H2Connection(config=H2Configuration(client_side=True))
        client.initiate_connection()
        client.send_headers(1, [(b':method', b'GET'), (b':scheme', b'https'),
                                (b':authority', b'example.invalid'), (b':path', b'/')],
                            end_stream=True)
        server = H2Connection(config=H2Configuration(client_side=False))
        server.initiate_connection()
        server.receive_data(client.data_to_send())
        server.send_headers(1, [(b':status', b'200')], end_stream=True)
        reader, writer = asyncio.StreamReader(), _Writer()
        reader.feed_data(server.data_to_send())
        boundary = _Readiness()

        async def connect(*args, **kwargs):
            await boundary.wait()
            return reader, writer

        transport = H2Transport()
        self.transports.append(transport)
        request = httpx.Request('GET', 'https://example.invalid/',
                                extensions={'timeout': {'connect': 0.5, 'read': 0.05,
                                                        'write': 0.05, 'pool': 0.05}})
        try:
            with patch('proxy.h2_transport.asyncio.open_connection', connect):
                await self.assert_stopped(transport.handle_async_request(request), boundary)
        finally:
            if transport.connection is not None:
                self.connections.append(transport.connection)
            else:
                writer.close()
        self.assertFalse(transport.connect_lock.locked())

    async def test_response_timeout_keeps_read_timeout_type(self):
        connection = self.connection()
        stream = self.stream(connection)
        with self.assertRaises(httpx.ReadTimeout):
            await stream.wait()
        self.assertTrue(connection.writer.closed)

    async def test_capacity_timeout_keeps_pool_timeout_type(self):
        connection = self.connection()
        with self.assertRaises(httpx.PoolTimeout):
            await connection.reserve({'pool': 0.01})
        self.assertFalse(connection.streams)

    async def test_window_timeout_keeps_write_timeout_type(self):
        connection = self.connection(write_timeout=0.01)
        stream = self.stream(connection)
        connection.h2.outbound_flow_control_window = 0
        request = httpx.Request('POST', 'https://example.invalid/', content=b'payload')
        with self.assertRaises(httpx.WriteTimeout):
            await connection.send_body(request, stream)

    async def test_drain_timeout_keeps_write_timeout_type(self):
        connection = self.connection(write_timeout=0.01)
        connection.writer.drain_boundary = asyncio.Event()
        with self.assertRaises(httpx.WriteTimeout):
            await connection.drain()
        self.assertFalse(connection.write_lock.locked())
        self.assertTrue(connection.writer.closed)

    async def test_tls_timeout_keeps_connect_timeout_type(self):
        entered = asyncio.Event()

        async def connect(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()

        transport = H2Transport()
        self.transports.append(transport)
        request = httpx.Request('GET', 'https://example.invalid/',
                                extensions={'timeout': {'connect': 0.01}})
        with patch('proxy.h2_transport.asyncio.open_connection', connect):
            with self.assertRaises(httpx.ConnectTimeout):
                await transport.handle_async_request(request)
        self.assertTrue(entered.is_set())
        self.assertIsNone(transport.connection)
        self.assertFalse(transport.connect_lock.locked())

    async def test_nonpositive_read_budget_expires_before_ready_event(self):
        for budget in (0, -0.01):
            with self.subTest(budget=budget):
                connection = self.connection()
                stream = self.stream(connection)
                stream.read_timeout = budget
                stream.changed.set()
                with self.assertRaises(httpx.ReadTimeout):
                    await stream.wait()

    async def test_nonpositive_write_budget_expires_before_immediate_drain(self):
        for budget in (0, -0.01):
            with self.subTest(budget=budget):
                connection = self.connection(write_timeout=budget)
                with self.assertRaises(httpx.WriteTimeout):
                    await connection.drain()
                self.assertFalse(connection.write_lock.locked())

    async def test_nonpositive_connect_budget_does_not_start_connection(self):
        for budget in (0, -0.01):
            with self.subTest(budget=budget):
                entered = False

                async def connect(*args, **kwargs):
                    nonlocal entered
                    entered = True
                    raise AssertionError('expired connect operation was started')

                transport = H2Transport()
                self.transports.append(transport)
                request = httpx.Request('GET', 'https://example.invalid/',
                                        extensions={'timeout': {'connect': budget}})
                with patch('proxy.h2_transport.asyncio.open_connection', connect):
                    with self.assertRaises(httpx.ConnectTimeout):
                        await transport.handle_async_request(request)
                self.assertFalse(entered)
                self.assertIsNone(transport.connection)

    async def test_nonpositive_pool_budget_keeps_capacity_timeout(self):
        for budget in (0, -0.01):
            with self.subTest(budget=budget):
                connection = self.connection()
                with self.assertRaises(httpx.PoolTimeout):
                    await connection.reserve({'pool': budget})
                self.assertFalse(connection.streams)

    async def test_none_read_write_and_pool_budgets_allow_readiness(self):
        async def completed(operation):
            task = asyncio.create_task(operation)
            self.owned.append(task)
            done, _ = await asyncio.wait({task}, timeout=1)
            self.assertIn(task, done, 'unlimited-budget operation ignored readiness')
            return task.result()

        connection = self.connection(write_timeout=None)
        stream = self.stream(connection)
        stream.read_timeout = None
        asyncio.get_running_loop().call_soon(stream.changed.set)
        await completed(stream.wait())
        connection.writer.drain_boundary = asyncio.Event()
        asyncio.get_running_loop().call_soon(connection.writer.drain_boundary.set)
        await completed(connection.drain())

        def capacity_available():
            connection.settings_received = True
            connection.changed.set()

        asyncio.get_running_loop().call_soon(capacity_available)
        reserved = await completed(connection.reserve({'pool': None}))
        self.assertIn(reserved.stream_id, connection.streams)

    async def test_none_connect_budget_keeps_connection_error_mapping(self):
        entered = False

        async def connect(*args, **kwargs):
            nonlocal entered
            entered = True
            raise OSError('owned unavailable transport')

        transport = H2Transport()
        self.transports.append(transport)
        request = httpx.Request('GET', 'https://example.invalid/',
                                extensions={'timeout': {'connect': None}})
        with patch('proxy.h2_transport.asyncio.open_connection', connect):
            with self.assertRaises(httpx.ConnectError) as error:
                await transport.handle_async_request(request)
        self.assertNotIsInstance(error.exception, httpx.ConnectTimeout)
        self.assertTrue(entered)
        self.assertIsNone(transport.connection)
