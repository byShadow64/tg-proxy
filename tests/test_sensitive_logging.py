import asyncio
import io
import logging
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, patch

from proxy import tg_ws_proxy
from proxy.config import ProxyConfig
from proxy.utils import SensitiveDataFormatter
from utils import tray_common
from utils.live_logs import LiveLogHandler


SECRET = "1234567890abcdef1234567890abcdef"
TOKEN = "abcdefghijklmno.pqrstuvwxyz012345.abcdefghijklmno"
URL = f"tg://proxy?server=127.0.0.1&port=1443&secret=dd{SECRET}"


class SensitiveDataFormatterTest(unittest.TestCase):
    def test_credentials_in_links_configs_and_startup_messages_are_redacted(self):
        formatter = SensitiveDataFormatter("%(message)s")
        messages = [
            f"Opening {URL}",
            f"https://t.me/proxy?server=127.0.0.1&SECRET=ee{SECRET}6578616d706c652e6f7267",
            f"Secret: {SECRET}",
            f"Generated secret: {SECRET}",
            f"Config: {{'secret': '{SECRET}', 'helper_token_dpapi': '{TOKEN}'}}",
            f'Config: {{"secret": "{SECRET}", "helper_token": "{TOKEN}"}}',
            f"token={TOKEN}",
        ]
        for message in messages:
            with self.subTest(message=message):
                record = logging.makeLogRecord({"msg": "%s", "args": (message,)})
                rendered = formatter.format(record)
                self.assertNotIn(SECRET, rendered)
                self.assertNotIn(TOKEN, rendered)
                self.assertIn("<redacted>", rendered)
                self.assertEqual(record.getMessage(), message)

    def test_current_credentials_are_also_redacted_from_tracebacks_and_stack_info(self):
        credentials = [SECRET, TOKEN]
        formatter = SensitiveDataFormatter("%(message)s", secrets=lambda: credentials)
        try:
            raise RuntimeError(f"Upstream rejected {SECRET.upper()} and {TOKEN}")
        except RuntimeError:
            record = logging.makeLogRecord({
                "msg": "Request failed", "exc_info": sys.exc_info(),
                "stack_info": f"Diagnostic stack contains {SECRET}",
            })
        rendered = formatter.format(record)
        self.assertIn("Traceback", rendered)
        self.assertNotIn(SECRET, rendered.lower())
        self.assertNotIn(TOKEN, rendered)
        # A formatter must follow changed runtime settings after a restart.
        credentials[:] = ["new-current-credential"]
        record = logging.makeLogRecord({"msg": "Rejected new-current-credential"})
        self.assertEqual(formatter.format(record), "Rejected <redacted>")


class LoggingIntegrationTest(unittest.TestCase):
    def test_bootstrap_does_not_dump_unknown_or_nested_config_credentials(self):
        config = {
            "verbose": False, "secret": SECRET,
            "ssh_password": "synthetic-private-password",
            "old_extension": {"credentials": ["synthetic-private-extension-key"]},
            "helper_token_dpapi": TOKEN,
        }
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(tray_common, "LOG_FILE", Path(folder) / "proxy.log"), \
                patch.object(tray_common, "save_config") as save, \
                patch.object(tray_common, "setup_logging"), \
                self.assertLogs(tray_common.log, level="INFO") as recorded:
            tray_common.bootstrap(config)
        save.assert_called_once_with(config)
        output = "\n".join(recorded.output)
        self.assertIn("Config loaded", output)
        for credential in (SECRET, TOKEN, "synthetic-private-password",
                           "synthetic-private-extension-key"):
            self.assertNotIn(credential, output)

    def setUp(self):
        self.root = logging.getLogger()
        self.previous_handlers = self.root.handlers[:]
        self.previous_level = self.root.level
        self.root.handlers = []
        self.logger = logging.getLogger("tg-mtproto-proxy")
        self.previous_logger_level = self.logger.level
        self.previous_asyncio_level = logging.getLogger("asyncio").level
        self.previous_http_levels = {
            name: logging.getLogger(name).level for name in ("httpx", "httpcore")
        }
        self.logger.setLevel(logging.NOTSET)

    def tearDown(self):
        for handler in self.root.handlers[:]:
            self.root.removeHandler(handler)
            handler.close()
        self.root.handlers = self.previous_handlers
        self.root.setLevel(self.previous_level)
        self.logger.setLevel(self.previous_logger_level)
        logging.getLogger("asyncio").setLevel(self.previous_asyncio_level)
        for name, level in self.previous_http_levels.items():
            logging.getLogger(name).setLevel(level)

    def test_tray_file_live_history_and_console_hide_credentials_without_changing_link(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as cleanup:
            cleanup.callback(self._close_handlers)
            log_path = Path(folder) / "proxy.log"
            console = io.StringIO()
            history = LiveLogHandler()
            config = ProxyConfig(secret=SECRET, helper_token=TOKEN)
            with patch.object(tray_common, "ensure_dirs"), \
                    patch.object(tray_common, "LOG_FILE", log_path), \
                    patch.object(tray_common, "live_logs", history), \
                    patch.object(tray_common, "proxy_config", config), \
                    patch.object(tray_common, "IS_FROZEN", False), \
                    patch("sys.stdout", console):
                tray_common.setup_logging()
                self.logger.info("Opening %s", URL)
                self.logger.info("Rejected Bearer %s", TOKEN)
                self.logger.info("Secret: %s", SECRET, extra={"connection_info": True})
                try:
                    raise RuntimeError(f"Rejected {SECRET} {TOKEN}")
                except RuntimeError:
                    self.logger.exception("Upstream failed")
                # Runtime values can change while the same log handlers live on.
                config.secret = "abcdef0123456789abcdef0123456789"
                self.logger.info("Rejected %s", config.secret)
                for handler in self.root.handlers:
                    handler.flush()
                outputs = [log_path.read_text(encoding="utf-8"),
                           "\n".join(history.read_since()[1]), console.getvalue()]
                for output in outputs:
                    self.assertIn("Opening tg://proxy?server=127.0.0.1", output)
                    self.assertIn("Traceback", output)
                    self.assertIn("Rejected Bearer <redacted>", output)
                    for credential in (SECRET, TOKEN, config.secret):
                        self.assertNotIn(credential, output)
                self.assertEqual(tray_common.tg_proxy_url({
                    "host": "127.0.0.1", "port": 1443, "secret": SECRET,
                }), URL)

    def _close_handlers(self):
        # Close Windows file handles before TemporaryDirectory removes them,
        # including when an assertion fails.
        for handler in self.root.handlers:
            handler.close()

    def test_cli_keeps_intentional_connection_output_but_redacts_file_and_other_messages(self):
        original_run = tg_ws_proxy._run

        async def run():
            self.logger.info("Unexpected URL: %s", URL)
            stop = asyncio.Event()
            stop.set()
            await original_run(stop)

        with tempfile.TemporaryDirectory() as folder, ExitStack() as cleanup:
            cleanup.callback(self._close_handlers)
            log_path = Path(folder) / "cli.log"
            console = io.StringIO()
            config = ProxyConfig()
            argv = ["proxy", "--secret", SECRET, "--port", "0",
                    "--pool-size", "0", "--no-cfproxy", "--log-file", str(log_path)]
            with patch.object(tg_ws_proxy, "proxy_config", config), \
                    patch.object(tg_ws_proxy, "start_cfproxy_domain_refresh"), \
                    patch.object(tg_ws_proxy.ws_pool, "warmup", AsyncMock()), \
                    patch.object(tg_ws_proxy.cf_worker_pool, "warmup", AsyncMock()), \
                    patch.object(tg_ws_proxy, "_run", run), \
                    patch("sys.argv", argv), patch("sys.stderr", console):
                tg_ws_proxy.main()
            for handler in self.root.handlers:
                handler.flush()
            saved = log_path.read_text(encoding="utf-8")
            self.assertNotIn(SECRET, saved)
            self.assertIn("secret=<redacted>", saved)
            visible = console.getvalue()
            self.assertIn(f"&secret=dd{SECRET}", visible)
            unexpected = next(line for line in visible.splitlines() if "Unexpected URL:" in line)
            self.assertNotIn(SECRET, unexpected)


if __name__ == "__main__":
    unittest.main()
