"""Admission must include sockets which haven't sent a TLS ClientHello yet."""
import asyncio
from pathlib import Path
import ssl
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from helper_server import HelperServer, create_listener_servers
from proxy.helper_conn import HelperConnection
from tests.test_helper_protocol import _make_certificate


class TLSAdmissionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        cert,key,self.fingerprint = _make_certificate(Path(self.temp.name))
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert,key)
        self.helper = HelperServer("a"*64)
        self.servers = await create_listener_servers(self.helper,
            SimpleNamespace(bind="127.0.0.1",secure_port=0,legacy_port=8443,allow_legacy=False),self.context)
        self.port = self.servers[0].sockets[0].getsockname()[1]
        self.clients = []

    async def asyncTearDown(self):
        for writer in self.clients:
            writer.close()
        for server in self.servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))
        await self.helper.close_clients()
        self.temp.cleanup()

    async def wait_active(self,count):
        async with asyncio.timeout(2):
            while self.helper._active != count:
                await asyncio.sleep(.01)

    async def test_pre_tls_slots_bound_raw_connections_and_expire(self):
        with patch("helper_server.MAX_CONNECTIONS",3), \
             patch("helper_server.MAX_CONNECTIONS_PER_IP",2), \
             patch("helper_server.HANDSHAKE_TIMEOUT",.3):
            for _ in range(2):
                _,writer=await asyncio.open_connection("127.0.0.1",self.port)
                self.clients.append(writer)
            await self.wait_active(2)
            reader,rejected=await asyncio.open_connection("127.0.0.1",self.port)
            self.clients.append(rejected)
            self.assertEqual(await asyncio.wait_for(reader.read(1),1),b"")
            self.assertEqual(self.helper._active,2)
            await self.wait_active(0)
            self.assertFalse(self.helper._per_ip)
            self.assertFalse(self.helper._tasks)

    async def test_shutdown_closes_pending_handshakes_without_waiting_fifteen_seconds(self):
        for _ in range(3):
            _,writer=await asyncio.open_connection("127.0.0.1",self.port)
            self.clients.append(writer)
        await self.wait_active(3)
        await asyncio.wait_for(self.helper.close_clients(),1)
        self.assertEqual(self.helper._active,0)
        self.assertFalse(self.helper._per_ip)
        self.assertFalse(self.helper._writers)

    async def test_eager_real_tls_and_private_auth_still_work(self):
        received=[]
        async def relay(reader,writer,domain,*,secure):
            received.append((domain,secure))
            from helper_server import write_frame
            await write_frame(writer,b"OK")
            await reader.read(1)
        self.helper._relay=relay
        route=sorted(self.helper._routes)[0]
        connection=await HelperConnection.connect_v2("127.0.0.1",self.port,self.fingerprint,"a"*64,route)
        self.assertEqual(received,[(route,True)])
        self.assertEqual(self.helper._active,1)
        await connection.close()
        await self.wait_active(0)

    async def test_older_streamwriter_without_convenience_start_tls_keeps_real_tls(self):
        received=[]
        async def relay(reader,writer,domain,*,secure):
            received.append(secure)
            from helper_server import write_frame
            await write_frame(writer,b"OK")
            await reader.read(1)
        self.helper._relay=relay
        with patch.object(asyncio.StreamWriter,"start_tls",None):
            connection=await HelperConnection.connect_v2("127.0.0.1",self.port,
                self.fingerprint,"a"*64,sorted(self.helper._routes)[0])
            self.assertEqual(received,[True])
            await connection.close()
            await self.wait_active(0)

    async def test_abandoned_and_malformed_handshakes_leave_no_slots(self):
        for _ in range(12):
            _,writer=await asyncio.open_connection("127.0.0.1",self.port)
            writer.write(b"not a TLS ClientHello")
            await writer.drain()
            writer.close()
            self.clients.append(writer)
        await self.wait_active(0)
        self.assertFalse(self.helper._per_ip)
