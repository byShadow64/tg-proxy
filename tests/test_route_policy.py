"""Destination checks happen before DNS, sockets, or background pool tasks."""
import unittest
from unittest.mock import AsyncMock, patch
from proxy.config import CFPROXY_DEFAULT_DOMAINS, parse_dc_ip_list, proxy_config
from proxy.pool import _WsPool
from proxy.raw_websocket import RawWebSocket
from proxy.route_policy import (require_telegram_ip, require_direct_route,
                                require_relay_hostname, is_telegram_ws_domain)
from proxy.utils import DC_DEFAULT_IPS, DC_TEST_IPS

class RoutePolicyTest(unittest.TestCase):
    def test_builtin_telegram_addresses_allowed(self):
        for value in set(DC_DEFAULT_IPS.values()) | set(DC_TEST_IPS.values()) | {'149.154.167.220'}:
            with self.subTest(value=value):
                self.assertEqual(require_telegram_ip(value), value)
        self.assertEqual(require_telegram_ip('2001:0B28:F23D:0000::1'), '2001:b28:f23d::1')

    def test_reviewed_cidr_ranges_and_boundaries(self):
        # Independent examples, not derived from the implementation catalog.
        for value in ('91.108.56.1', '91.108.4.1', '91.108.8.1', '91.108.16.1',
                      '91.108.12.1', '149.154.160.1', '149.154.175.254',
                      '91.105.192.1', '91.105.193.254', '91.108.20.1',
                      '185.76.151.1', '2001:b28:f23f::1', '2001:67c:4e8::1',
                      '2001:b28:f23c::1', '2a0a:f280::1'):
            with self.subTest(value=value):
                self.assertEqual(require_telegram_ip(value), value)
        for value in ('149.154.159.255', '149.154.176.0', '91.105.191.255',
                      '91.105.194.0', '185.76.150.255', '185.76.152.0',
                      '2001:b28:f23e::1', '2a0a:f281::1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                require_telegram_ip(value)

    def test_non_telegram_nonliteral_addresses_rejected(self):
        for value in ('1.2.3.4', '8.8.8.8', '192.0.2.1', '127.0.0.1', '10.0.0.1',
                      '169.254.169.254', '224.0.0.1', '0.0.0.0', '::1', 'fc00::1',
                      '2001:db8::1', '::ffff:149.154.167.220', '2001:b28:f23d::1%eth0',
                      'kws2.web.telegram.org', '149.154.167.220:443', '', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                require_telegram_ip(value)

    def test_supported_direct_dc_ids(self):
        for dc in (1, 2, 3, 4, 5, 203):
            self.assertEqual(require_direct_route(dc, '149.154.167.220'), '149.154.167.220')
        for dc in (0, 6, -2, 10002, 999, True, '2', None):
            with self.subTest(dc=dc), self.assertRaises(ValueError):
                require_direct_route(dc, '149.154.167.220')

    def test_config_parser_rejects_arbitrary_direct_targets(self):
        for entry in ('2:1.2.3.4', '2:127.0.0.1', '6:149.154.167.220',
                      '-2:149.154.167.220', '10002:149.154.167.220'):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                parse_dc_ip_list([entry])

    def test_cf_worker_names_and_catalog_preserved(self):
        for value in (*CFPROXY_DEFAULT_DOMAINS, 'my-worker.example.workers.dev',
                      'Custom-Relay.Example.com', 'xn--e1afmkfd.example'):
            with self.subTest(value=value):
                self.assertEqual(require_relay_hostname(value), value)

    def test_relay_is_not_url_or_socket_address(self):
        for value in ('https://relay.example', 'relay.example:443', 'user@relay.example',
                      'relay.example/path', 'relay.example?x=y', 'relay.example#fragment',
                      'relay.example\r\nHost: bad', 'relay.example ', ' relay.example',
                      '127.0.0.1', '149.154.167.220', '[::1]', '::1', 'пример.рф',
                      '-relay.example', 'relay-.example', 'relay..example',
                      'a' * 64 + '.example', '', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                require_relay_hostname(value)

    def test_exact_telegram_ws_names(self):
        for dc in (1, 2, 3, 4, 5):
            for suffix in ('', '-1'):
                self.assertTrue(is_telegram_ws_domain(f'kws{dc}{suffix}.web.telegram.org'))
        for domain in ('eviltelegram.org', 'kws2.web.telegram.org.evil.example',
                       'kws2.web.telegram.org:443', 'kws2.web.telegram.org/path',
                       'kws0.web.telegram.org', 'kws999.web.telegram.org', '', None):
            with self.subTest(domain=domain):
                self.assertFalse(is_telegram_ws_domain(domain))

class RouteEgressTest(unittest.IsolatedAsyncioTestCase):
    async def test_bad_direct_ip_and_relay_shapes_never_dial(self):
        cases = [('1.2.3.4', 'kws2.web.telegram.org'),
                 ('127.0.0.1', 'kws2.web.telegram.org'),
                 ('kws2.web.telegram.org', 'kws2.web.telegram.org'),
                 ('relay.example:6881', 'relay.example:6881'),
                 ('relay.example/path', 'relay.example/path'),
                 ('relay.example', 'relay.example\r\nHost: bad')]
        for host, domain in cases:
            with self.subTest(host=host, domain=domain), patch('asyncio.open_connection', AsyncMock()) as dial:
                with self.assertRaises(ValueError):
                    await RawWebSocket.connect(host, domain)
                dial.assert_not_awaited()

    async def test_valid_cf_worker_reaches_mocked_transport(self):
        class StopBeforeSocket(Exception):
            pass
        with patch('asyncio.open_connection', AsyncMock(side_effect=StopBeforeSocket)) as dial:
            with self.assertRaises(StopBeforeSocket):
                await RawWebSocket.connect('my-worker.example.workers.dev', 'my-worker.example.workers.dev')
            dial.assert_awaited_once()
            self.assertEqual(dial.call_args.args[:2], ('my-worker.example.workers.dev', 443))

    async def test_valid_direct_and_default_cf_endpoints_reach_mocked_dial(self):
        class StopBeforeSocket(Exception):
            pass
        cf_host = 'kws2.' + CFPROXY_DEFAULT_DOMAINS[0]
        for host, domain in (('149.154.167.220', 'kws2.web.telegram.org'),
                             ('2001:b28:f23d::1', 'kws2.web.telegram.org'),
                             (cf_host, cf_host)):
            with self.subTest(host=host), patch('asyncio.open_connection',
                    AsyncMock(side_effect=StopBeforeSocket)) as dial:
                with self.assertRaises(StopBeforeSocket):
                    await RawWebSocket.connect(host, domain)
                dial.assert_awaited_once()
                self.assertEqual(dial.call_args.args[:2], (host, 443))

    async def test_forced_test_pool_skips_production_only_dc(self):
        pool = _WsPool()
        with patch.object(proxy_config, 'dc_redirects',
                          {2: '149.154.167.220', 4: '149.154.167.220'}), \
                patch.object(proxy_config, 'force_test_dc', True), \
                patch.object(pool, '_schedule_refill') as refill, \
                patch('asyncio.open_connection', AsyncMock()) as dial:
            await pool.warmup()
            self.assertEqual([call.args[0] for call in refill.call_args_list],
                             [(2, False, True), (2, True, True)])
            refill.reset_mock()
            self.assertIsNone(await pool.get(4, False, is_test_dc=True))
            refill.assert_not_called()
            dial.assert_not_awaited()

    async def test_pool_raw_config_cannot_bypass_policy(self):
        pool = _WsPool()
        with patch.object(proxy_config, 'dc_redirects', {2: '127.0.0.1', 6: '149.154.167.220'}), \
                patch.object(pool, '_schedule_refill') as refill, \
                patch('asyncio.open_connection', AsyncMock()) as dial:
            await pool.warmup()
            self.assertIsNone(await pool.get(2, False))
            self.assertIsNone(await pool.get(6, False))
            refill.assert_not_called()
            dial.assert_not_awaited()

    async def test_pool_connect_one_validates_before_ws(self):
        with patch('proxy.pool.RawWebSocket.connect', AsyncMock()) as connect:
            self.assertIsNone(await _WsPool()._connect_one('1.2.3.4', ['kws2.web.telegram.org']))
            connect.assert_not_awaited()

    async def test_h2_lane_validates_before_client_creation(self):
        from proxy.cf_h2 import _HttpLane
        for host in ('relay.example:6881', 'https://relay.example', 'relay.example/path', '127.0.0.1'):
            with self.subTest(host=host), patch('proxy.cf_h2.httpx.AsyncClient') as client:
                with self.assertRaises(ValueError):
                    _HttpLane(host, 0)
                client.assert_not_called()

if __name__ == '__main__':
    unittest.main()
