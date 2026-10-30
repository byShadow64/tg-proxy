"""Untrusted loopback clients cannot keep rejected sessions or bypass limits."""
import asyncio
import unittest
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

from proxy import tg_ws_proxy
from proxy.config import ProxyConfig


class ProxyAdmissionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.stack = ExitStack()
        config = ProxyConfig(host='127.0.0.1', port=0, pool_size=0,
                             secret='a' * 32, fake_tls_domain='')
        self.stack.enter_context(patch.object(tg_ws_proxy, 'proxy_config', config))
        self.stack.enter_context(patch.object(tg_ws_proxy, 'start_cfproxy_domain_refresh'))
        for pool in (tg_ws_proxy.ws_pool, tg_ws_proxy.cf_worker_pool):
            self.stack.enter_context(patch.object(pool, 'warmup', AsyncMock()))
        self.stack.enter_context(patch.object(tg_ws_proxy, 'MAX_CLIENT_CONNECTIONS', 2))
        self.stack.enter_context(patch.object(tg_ws_proxy, 'MAX_CLIENT_CONNECTIONS_PER_IP', 1))
        self.stopping = asyncio.Event()
        self.running = asyncio.create_task(tg_ws_proxy._run(self.stopping))
        for _ in range(100):
            server = tg_ws_proxy._server_instance
            if server is not None:
                break
            await asyncio.sleep(0.01)
        else:
            self.fail('test listener did not start')
        self.port = server.sockets[0].getsockname()[1]
        self.writers = []

    async def asyncTearDown(self):
        for writer in self.writers:
            writer.close()
        self.stopping.set()
        await asyncio.wait_for(self.running, 2)
        await asyncio.gather(*(w.wait_closed() for w in self.writers),
                             return_exceptions=True)
        self.stack.close()

    async def connect(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        self.writers.append(writer)
        return reader, writer

    async def test_invalid_secret_closes_without_waiting_for_eof(self):
        reader, writer = await self.connect()
        writer.write(b'\0' * 64)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 0.5), b'')

    async def test_idle_client_limit_is_released_after_disconnect(self):
        first, first_writer = await self.connect()
        second, _ = await self.connect()
        self.assertEqual(await asyncio.wait_for(second.read(), 0.5), b'')
        self.assertEqual(len(tg_ws_proxy._client_tasks), 1)
        first_writer.close()
        await first_writer.wait_closed()
        for _ in range(100):
            if not tg_ws_proxy._client_tasks:
                break
            await asyncio.sleep(0.001)
        third, third_writer = await self.connect()
        third_writer.write(b'\0' * 64)
        await third_writer.drain()
        self.assertEqual(await asyncio.wait_for(third.read(), 0.5), b'')

    async def test_global_limit_is_enforced_before_starting_handler(self):
        with patch.object(tg_ws_proxy, 'MAX_CLIENT_CONNECTIONS_PER_IP', 10):
            await self.connect()
            await self.connect()
            rejected, _ = await self.connect()
            self.assertEqual(await asyncio.wait_for(rejected.read(), 0.5), b'')
            self.assertEqual(len(tg_ws_proxy._client_tasks), 2)
