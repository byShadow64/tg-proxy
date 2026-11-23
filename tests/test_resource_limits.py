"""Small synthetic settings and pool boundaries; never allocate excessive resources."""
import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from proxy.config import ProxyConfig, bounded_pool_size, resource_value
from proxy.pool import _WsPool
from proxy import tg_ws_proxy
from ui.settings import validate_settings
from utils import tray_common
from utils.default_config import default_tray_config


class ResourceLimitsTest(unittest.TestCase):
    def test_shared_ranges_accept_boundaries_and_reject_bad_types_or_fractional_pools(self):
        for key, values in (("pool_size", (0, 32)), ("buf_kb", (4, 4096)), ("log_max_mb", (1/32, 1024))):
            for value in values:
                self.assertEqual(resource_value(key, str(value)), value)
            for value in (True, None, "nan", "inf", "-inf", -1, "1e100"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    resource_value(key, value)
        with self.assertRaises(ValueError): resource_value("pool_size", "4.5")
        self.assertEqual(bounded_pool_size(33), 0)
        self.assertEqual(bounded_pool_size("untrusted"), 0)

    def test_ui_rejects_out_of_range_instead_of_silently_saving_it(self):
        defaults = default_tray_config()
        values = {"host": "127.0.0.1", "port": "1443", "secret": "a" * 32, "dc_ip": "",
                  "pool_size": "4", "buf_kb": "256", "log_max_mb": "5"}
        self.assertIsInstance(validate_settings(values, defaults), dict)
        for key, value in (("pool_size", "33"), ("buf_kb", "4097"), ("log_max_mb", "1025")):
            with self.subTest(key=key):
                self.assertIsInstance(validate_settings({**values, key: value}, defaults), str)

    def test_invalid_runtime_settings_do_not_partially_change_applied_profile(self):
        runtime = ProxyConfig(secret="b" * 32)
        config = {**default_tray_config(), "secret": "a" * 32, "pool_size": 33}
        with patch.object(tray_common, "proxy_config", runtime):
            self.assertFalse(tray_common.apply_proxy_config(config))
        self.assertEqual(runtime.secret, "b" * 32)
        self.assertEqual(runtime.pool_size, 4)


class PoolLimitTest(unittest.IsolatedAsyncioTestCase):
    async def test_direct_pool_rejects_invalid_internal_size_without_dial_tasks(self):
        pool = _WsPool()
        with patch("proxy.pool.proxy_config", ProxyConfig(pool_size=33)), \
                patch.object(pool, "_connect_one", AsyncMock()) as connect:
            await pool._refill((2, False, False), "149.154.167.220", ["kws2.web.telegram.org"])
        connect.assert_not_awaited()

    async def test_socket_configuration_failure_still_closes_session_and_balances_stats(self):
        writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
        writer.get_extra_info.return_value = None
        before = tg_ws_proxy.stats.connections_active
        with patch.object(tg_ws_proxy, "set_sock_opts", side_effect=OverflowError("synthetic buffer")):
            await tg_ws_proxy._handle_client(asyncio.StreamReader(), writer, bytes(16))
        writer.close.assert_called_once()
        self.assertEqual(tg_ws_proxy.stats.connections_active, before)
