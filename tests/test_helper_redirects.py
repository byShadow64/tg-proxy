"""No network: exercise the real WebSocket redirect loops with mocked dials."""
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from websockets.datastructures import Headers
from websockets.exceptions import InvalidStatus, RedirectHandshake
from websockets.http11 import Response
from websockets.legacy.client import Connect as LegacyConnect

try:
    from websockets.asyncio.client import connect as ModernConnect
except ImportError:  # websockets 12 uses the legacy asyncio implementation.
    ModernConnect = None

from helper_server import _telegram_connect


TARGETS = (
    "wss://attacker.example:6881/relay",
    "wss://127.0.0.1:12345/relay",
    "wss://[::1]:12345/relay",
    "wss://kws2.web.telegram.org:8443/apiws",
    "wss://kws3.web.telegram.org/apiws",
    "/another-path",
)
ORIGIN = "wss://kws2.web.telegram.org/apiws"


class HelperRedirectTest(unittest.IsolatedAsyncioTestCase):
    async def test_supported_connectors_accept_success_without_redirect(self):
        for connector in (LegacyConnect, ModernConnect):
            if connector is None:
                continue
            with self.subTest(api=connector.__module__):
                upstream = SimpleNamespace(
                    handshake=AsyncMock(), transport=Mock(), start_keepalive=Mock(),
                    origin=None, available_extensions=None,
                    available_subprotocols=None, extra_headers=None,
                )
                with patch("helper_server.websockets.connect", connector):
                    connection = _telegram_connect(ORIGIN)
                if connector is LegacyConnect:
                    name, result = "_create_connection", (Mock(), upstream)
                else:
                    name, result = "create_connection", upstream
                dial = AsyncMock(return_value=result)
                with patch.object(connection, name, dial):
                    self.assertIs(await connection, upstream)
                dial.assert_awaited_once()
                upstream.handshake.assert_awaited_once()
                upstream.transport.abort.assert_not_called()

    @unittest.skipIf(ModernConnect is None, "new asyncio API unavailable")
    async def test_modern_redirect_never_causes_a_second_dial(self):
        for status in (300, 301, 302, 303, 307, 308):
            for target in TARGETS:
                with self.subTest(status=status, target=target):
                    failure = InvalidStatus(Response(
                        status, "Redirect", Headers({"Location": target})))
                    upstream = SimpleNamespace(
                        handshake=AsyncMock(side_effect=failure), transport=Mock())
                    with patch("helper_server.websockets.connect", ModernConnect):
                        connection = _telegram_connect(ORIGIN)
                    dial = AsyncMock(return_value=upstream)
                    with patch.object(connection, "create_connection", dial):
                        with self.assertRaises(InvalidStatus):
                            await connection
                    dial.assert_awaited_once()
                    upstream.transport.abort.assert_called_once()
                    self.assertEqual(connection.uri, ORIGIN)

    async def test_legacy_redirect_never_causes_a_second_dial(self):
        for target in TARGETS:
            with self.subTest(target=target):
                upstream = SimpleNamespace(
                    handshake=AsyncMock(side_effect=RedirectHandshake(target)),
                    fail_connection=Mock(), wait_closed=AsyncMock(),
                    origin=None, available_extensions=None,
                    available_subprotocols=None, extra_headers=None,
                )
                with patch("helper_server.websockets.connect", LegacyConnect):
                    connection = _telegram_connect(ORIGIN)
                dial = AsyncMock(return_value=(Mock(), upstream))
                with patch.object(connection, "_create_connection", dial):
                    with self.assertRaisesRegex(ConnectionError, "redirects are not permitted"):
                        await connection
                dial.assert_awaited_once()
                upstream.fail_connection.assert_called_once()
                upstream.wait_closed.assert_awaited_once()
                self.assertEqual(connection._uri, ORIGIN)

    async def test_unknown_connector_api_fails_before_await(self):
        with patch("helper_server.websockets.connect", return_value=object()):
            with self.assertRaisesRegex(RuntimeError, "redirect policy API"):
                _telegram_connect(ORIGIN)


if __name__ == "__main__":
    unittest.main()
