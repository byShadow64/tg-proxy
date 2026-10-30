"""Untrusted ingress never opens an upstream before a valid Telegram init."""
import asyncio
import hashlib
import os
import struct
import unittest
from types import SimpleNamespace
from contextlib import ExitStack
from unittest.mock import AsyncMock, Mock, patch

from proxy import tg_ws_proxy
from proxy.config import ProxyConfig
from proxy._aes import Cipher, algorithms, modes
from proxy.utils import (DC_DEFAULT_IPS, DC_TEST_IPS, PROTO_TAG_ABRIDGED,
                         PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE)
from tests.test_fake_tls import _client_hello
from proxy.fake_tls import wrap_tls_record

SECRET = bytes.fromhex('00112233445566778899aabbccddeeff')
TAGS = (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE)
TORRENT = b'\x13BitTorrent protocol' + bytes(8 + 20 + 20)


def client_init(dc=2, tag=PROTO_TAG_INTERMEDIATE, secret=SECRET):
    raw = bytearray(os.urandom(64))
    # Plain transport init is not a TLS record.
    raw[0] = 0x42
    key = hashlib.sha256(bytes(raw[8:40]) + secret).digest()
    cipher = Cipher(algorithms.AES(key), modes.CTR(bytes(raw[40:56]))).encryptor()
    raw[56:64] = tag + struct.pack('<h', dc) + b'\0\0'
    tail = cipher.update(bytes(raw))[56:64]
    raw[56:64] = tail
    return bytes(raw)


class TelegramOnlyTest(unittest.IsolatedAsyncioTestCase):
    async def run_input(self, payload, *, masking='', forced=False, fragmented=False,
                        helper=False, pool_hit=True, registry=False):
        reader = asyncio.StreamReader()
        writer = Mock(wait_closed=AsyncMock(), drain=AsyncMock())
        writer.get_extra_info.return_value = None
        config = ProxyConfig(fake_tls_domain=masking, force_test_dc=forced,
                             helper_registry=registry,
                             helper_mode='tls-pin' if helper else 'off',
                             helper_host='helper.example' if helper else '')
        ws = Mock(send=AsyncMock())
        with ExitStack() as stack:
            stack.enter_context(patch.object(tg_ws_proxy, 'proxy_config', config))
            stack.enter_context(patch.object(tg_ws_proxy, 'set_sock_opts'))
            get = stack.enter_context(patch.object(tg_ws_proxy.ws_pool, 'get',
                AsyncMock(return_value=ws if pool_hit else None)))
            fallback = stack.enter_context(patch.object(tg_ws_proxy, 'do_fallback', AsyncMock()))
            bridge = stack.enter_context(patch.object(tg_ws_proxy, 'bridge_ws_reencrypt', AsyncMock()))
            connect = stack.enter_context(patch.object(tg_ws_proxy.HelperConnection,
                'connect_v2', AsyncMock(return_value=ws)))
            # No test can send bytes to real internet destinations.
            network = stack.enter_context(patch('asyncio.open_connection',
                AsyncMock(side_effect=AssertionError('unexpected upstream socket'))))
            task = asyncio.create_task(tg_ws_proxy._handle_client(reader, writer, SECRET))
            if fragmented:
                for byte in payload:
                    reader.feed_data(bytes([byte]))
                    await asyncio.sleep(0)
            else:
                reader.feed_data(payload)
            reader.feed_eof()
            await asyncio.wait_for(task, 2)
        writer.close.assert_called_once()
        return get, fallback, bridge, connect, network

    async def assert_rejected(self, payload, **kwargs):
        for call in await self.run_input(payload, **kwargs):
            call.assert_not_awaited()

    async def test_non_telegram_protocols_never_reach_upstream(self):
        for payload in (TORRENT, b'\x05\x01\x00',
                        b'CONNECT 1.2.3.4:6881 HTTP/1.1\r\n\r\n',
                        b'GET / HTTP/1.1\r\n\r\n', bytes(64), b''):
            for fragmented in (False, True):
                with self.subTest(payload=payload[:20], fragmented=fragmented):
                    await self.assert_rejected(payload, fragmented=fragmented)

    async def test_non_tls_with_camouflage_never_reaches_upstream(self):
        await self.assert_rejected(TORRENT, masking='mask.example', fragmented=True)

    async def test_unknown_dc_inside_valid_fake_tls_is_rejected(self):
        payload = _client_hello(secret=SECRET) + wrap_tls_record(client_init(6))
        await self.assert_rejected(payload, masking='mask.example')

    def test_wrong_init_length_is_rejected(self):
        for size in (0, 1, 63, 65, 68):
            self.assertIsNone(tg_ws_proxy._try_handshake(bytes(size), SECRET))

    async def test_bad_secret_or_protocol_never_reaches_upstream(self):
        for payload in (client_init(secret=bytes(16)), client_init(tag=b'nope')):
            await self.assert_rejected(payload)

    async def test_unknown_dc_rejected_even_with_valid_secret(self):
        for dc in (0, 6, 9999, 10000, 10004, 10203, 32767, -6):
            for helper in (False, True):
                with self.subTest(dc=dc, helper=helper):
                    await self.assert_rejected(client_init(dc), helper=helper)

    async def test_force_test_dc_rejects_non_test_dc(self):
        for dc in (4, 5, 203):
            await self.assert_rejected(client_init(dc), forced=True)

    async def test_supported_transports_dc_and_media_route_normally(self):
        for ids, test in ((DC_DEFAULT_IPS, False), (DC_TEST_IPS, True)):
            for dc in ids:
                for tag in TAGS:
                    for media in (False, True):
                        wire_dc = dc + (10000 if test else 0)
                        wire_dc *= -1 if media else 1
                        with self.subTest(dc=wire_dc, tag=tag):
                            get, fallback, bridge, connect, network = await self.run_input(
                                client_init(wire_dc, tag))
                            get.assert_awaited_once_with(dc, media, is_test_dc=test)
                            bridge.assert_awaited_once()
                            fallback.assert_not_awaited()
                            connect.assert_not_awaited()
                            network.assert_not_awaited()

    async def test_valid_forced_test_and_media_ids_route_normally(self):
        for dc in (1, 2, 3):
            for wire in (dc, -dc, 10000 + dc, -(10000 + dc)):
                get, _, bridge, _, network = await self.run_input(client_init(wire), forced=True)
                get.assert_awaited_once_with(dc, wire < 0, is_test_dc=True)
                bridge.assert_awaited_once()
                network.assert_not_awaited()

    def test_explicit_supported_catalogs(self):
        self.assertEqual(set(DC_DEFAULT_IPS), {1, 2, 3, 4, 5, 203})
        self.assertEqual(set(DC_TEST_IPS), {1, 2, 3})

    async def test_fake_tls_does_not_bypass_inner_authentication(self):
        payload = _client_hello(secret=SECRET) + wrap_tls_record(client_init(secret=bytes(16)))
        await self.assert_rejected(payload, masking='mask.example')

    async def test_valid_fake_tls_still_routes(self):
        payload = _client_hello(secret=SECRET) + wrap_tls_record(client_init())
        get, _, bridge, _, network = await self.run_input(
            payload, masking='mask.example', fragmented=True)
        get.assert_awaited_once()
        bridge.assert_awaited_once()
        network.assert_not_awaited()

    async def test_rejected_fake_tls_never_relays_masking_or_appended_torrent(self):
        for payload in (_client_hello(secret=bytes(16)),
                        b'\x16\x03\x01\x00\x01\x01',
                        _client_hello(secret=bytes(16)) + TORRENT):
            for fragmented in (False, True):
                await self.assert_rejected(payload, masking='mask.example', fragmented=fragmented)

    async def test_valid_init_preserves_helper_and_fallback_paths(self):
        _, _, bridge, connect, network = await self.run_input(client_init(), helper=True)
        connect.assert_awaited_once()
        bridge.assert_awaited_once()
        network.assert_not_awaited()
        _, fallback, bridge, _, network = await self.run_input(client_init(), pool_hit=False)
        fallback.assert_awaited_once()
        bridge.assert_not_awaited()
        network.assert_not_awaited()

    async def test_invalid_input_never_requests_registered_helper_lease(self):
        with patch('utils.helper_registry.discover_helper') as discover:
            for payload in (TORRENT, client_init(6), client_init(0),
                            client_init(secret=bytes(16))):
                with self.subTest(payload=payload[:8]):
                    await self.assert_rejected(payload, helper=True, registry=True)
            discover.assert_not_called()

    async def test_valid_registered_helper_uses_lease_credentials(self):
        lease = SimpleNamespace(port=8444, fingerprint='b' * 64, token='synthetic-lease')
        with patch('utils.helper_registry.discover_helper', return_value=lease) as discover:
            _, fallback, bridge, connect, network = await self.run_input(
                client_init(), helper=True, registry=True)
            discover.assert_called_once()
            self.assertTrue(discover.call_args.kwargs['cancel_event'].is_set())
        connect.assert_awaited_once_with('helper.example', lease.port, lease.fingerprint,
                                        lease.token, 'kws2.web.telegram.org')
        bridge.assert_awaited_once()
        fallback.assert_not_awaited()
        network.assert_not_awaited()


if __name__ == '__main__':
    unittest.main()
