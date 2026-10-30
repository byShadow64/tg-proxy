import asyncio
import base64
import dataclasses
import hashlib
import logging
import socket
import ssl
import tempfile
import threading
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from proxy.config import ProxyConfig
from proxy.helper_conn import HelperConnection
from proxy.raw_websocket import WsHandshakeError
from tests.test_helper_protocol import _make_certificate
from utils import connection_diagnostics as d


def snapshot(**config):
    return d.make_snapshot({"cfproxy": False, "dc_ip": [], **config}, running=True)


class SnapshotTest(unittest.TestCase):
    def test_snapshot_is_immutable_detached_and_hides_private_fields(self):
        active = ProxyConfig(helper_mode="tls-pin", helper_host="private.example",
            helper_token="PRIVATE-TOKEN", helper_fingerprint="a" * 64)
        cfg = {"dc_ip": ["2:149.154.167.220"], "secret": "PRIVATE-SECRET"}
        first = d.make_snapshot(cfg, running=True, active=active, generation=1)
        active.dc_redirects.clear()
        cfg["dc_ip"].clear()
        self.assertEqual(len(first.redirects), 2)
        self.assertNotIn("PRIVATE", repr(first))
        self.assertNotIn("private.example", repr(first))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.running = False

    def test_identity_covers_saved_network_changes_active_state_and_lifecycle(self):
        active = ProxyConfig()
        cfg = {"port": 1443, "appearance": "dark"}
        baseline = d.make_snapshot(cfg, running=True, active=active, generation=1)
        self.assertEqual(baseline.identity, d.make_snapshot({**cfg, "appearance": "light"},
            running=True, active=active, generation=1).identity)
        for arguments in ({"config": {**cfg, "port": 1444}, "generation": 1},
                          {"config": cfg, "generation": 2}):
            changed = d.make_snapshot(arguments["config"], running=True, active=active,
                                      generation=arguments["generation"])
            self.assertNotEqual(baseline.identity, changed.identity)
        active.helper_token = "changed"
        self.assertNotEqual(baseline.identity, d.make_snapshot(cfg, running=True,
            active=active, generation=1).identity)

    def test_decrypt_only_supplied_enabled_config_not_running_active_state(self):
        cfg = {"helper_enabled": True, "helper_mode": "tls-pin", "helper_token_dpapi": "ciphertext"}
        with patch("utils.secure_storage.unprotect_token", return_value="PRIVATE") as decrypt:
            value = d.make_snapshot(cfg, running=False)
            self.assertEqual(value.helper_token, "PRIVATE")
            decrypt.assert_called_once_with("ciphertext")
            decrypt.reset_mock()
            d.make_snapshot(cfg, running=True, active=ProxyConfig())
            d.make_snapshot({**cfg, "helper_enabled": False}, running=False)
            decrypt.assert_not_called()

    def test_invalid_saved_redirects_do_not_replace_active_mapping(self):
        value = d.make_snapshot({"dc_ip": ["broken"]}, running=True, active=ProxyConfig())
        self.assertFalse(value.invalid)
        self.assertEqual(len(value.redirects), 2)
        self.assertTrue(d.make_snapshot({"dc_ip": ["broken"]}, running=False).invalid)


class PlanningTest(unittest.TestCase):
    def test_candidates_bounded_and_coverage_uses_complete_configured_list(self):
        value = snapshot(cfproxy=True, cfproxy_user_domain_enabled=True,
            cfproxy_user_domain=[f"domain{i}.example" for i in range(7)],
            cfproxy_worker_enabled=True, cfproxy_worker_domain=[f"worker{i}.example" for i in range(5)])
        probes, totals = d._build_probes(value)
        self.assertEqual(sum(p.kind == "cf" for p in probes), 6 * 3)
        self.assertEqual(sum(p.kind == "worker" for p in probes), 6 * 3)
        self.assertEqual(totals, {"cf": 42, "worker": 30})
        worker = next(p for p in probes if p.kind == "worker")
        self.assertEqual(worker.path, "/apiws?dst=149.154.175.50&dc=1")
        self.assertIsNone(worker.media)

    def test_no_secure_and_legacy_never_trigger_insecure_or_unconfirmed_probes(self):
        value = snapshot(no_secure=True, cfproxy=True, cfproxy_worker_enabled=True,
            cfproxy_worker_domain=["worker.example"], helper_enabled=True, helper_mode="legacy")
        probes, _ = d._build_probes(value)
        self.assertTrue(all(p.skip == "insecure_skipped" for p in probes if p.kind in ("cf", "worker")))
        self.assertTrue(all(p.skip == "legacy_unconfirmed" for p in probes if p.kind == "helper"))
        self.assertTrue(all(p.skip for p in probes if p.kind in ("h2", "tcp")))

    def test_wildcard_bind_checks_loopback_and_test_dc_path_is_preserved(self):
        value = snapshot(host="0.0.0.0", force_test_dc=True, dc_ip=["2:149.154.167.40"])
        probes, _ = d._build_probes(value)
        self.assertEqual(probes[0].host, "127.0.0.1")
        direct = next(p for p in probes if p.kind == "direct" and p.dc == 2)
        self.assertEqual(direct.path, "/apiws_test")
        self.assertTrue(all(p.skip == "not_applicable" for p in probes if p.kind == "helper"))
        self.assertEqual({p.dc for p in probes if p.dc is not None}, {1, 2, 3})

    def test_test_dc_worker_uses_actual_test_destinations_even_when_cf_disabled(self):
        value = snapshot(force_test_dc=True, cfproxy_worker_enabled=True,
            cfproxy_worker_domain=["worker.example"])
        probes, totals = d._build_probes(value)
        workers = [p for p in probes if p.kind == "worker"]
        self.assertEqual([p.path for p in workers], [
            "/apiws?dst=149.154.175.10&dc=1", "/apiws?dst=149.154.167.40&dc=2",
            "/apiws?dst=149.154.175.117&dc=3"])
        self.assertFalse(any(p.skip for p in workers))
        self.assertEqual(totals["worker"], 3)


class RunnerTest(unittest.TestCase):
    def run_probes(self, probes, connect, cancel=None, emit=None, **timing):
        with patch.object(d, "_build_probes", return_value=(probes, {})), \
                patch.object(d, "_connect", connect), \
                (patch.multiple(d, **timing) if timing else nullcontext()):
            return d.run_diagnostics(snapshot(), cancel or threading.Event(), emit or (lambda event: None))

    def test_four_concurrent_connections_and_cleanup_before_releasing_slot(self):
        current = maximum = closed = 0

        async def connect(probe, _):
            nonlocal current, maximum
            current += 1
            maximum = max(current, maximum)
            await asyncio.sleep(.015)

            async def close():
                nonlocal current, closed
                await asyncio.sleep(.01)
                current -= 1
                closed += 1

            return SimpleNamespace(close=close, writer=Mock())

        probes = [d._Probe("direct", dc=2, host="127.0.0.1", domain="example.org") for _ in range(13)]
        events = []
        report = self.run_probes(probes, connect, emit=events.append)
        self.assertEqual(maximum, 4)
        self.assertEqual(closed, 13)
        self.assertEqual(report.status, "complete")
        self.assertEqual([event["completed"] for event in events], list(range(1, 14)))
        self.assertTrue(all(result.status == "ok" for result in report.results))

    def test_cancel_stops_remaining_checks_and_closes_owned_connections(self):
        cancel = threading.Event()
        closed = []

        async def connect(probe, _):
            async def close():
                closed.append(True)
            await asyncio.sleep(.01)
            return SimpleNamespace(close=close, writer=Mock())

        def emit(event):
            if event["completed"] == 1:
                cancel.set()

        report = self.run_probes([d._Probe("direct") for _ in range(20)], connect, cancel, emit)
        self.assertEqual(report.status, "cancelled")
        self.assertTrue(closed)
        self.assertTrue(any(result.status == "cancelled" for result in report.results))
        self.assertEqual(report.recommendation, "retry")

    def test_whole_deadline_does_not_wait_for_all_queued_attempts(self):
        async def connect(*_):
            await asyncio.sleep(60)
        begin = time.monotonic()
        report = self.run_probes([d._Probe("direct") for _ in range(30)], connect, RUN_TIMEOUT=.08)
        self.assertLess(time.monotonic() - begin, 1)
        self.assertEqual(report.status, "partial")
        self.assertTrue(all(result.status == "incomplete" for result in report.results))

    def test_stuck_os_dns_is_daemon_bounded_and_does_not_delay_loop_shutdown(self):
        release = threading.Event()
        lock = threading.Lock()
        calls = []

        def blocked_dns(*args, **kwargs):
            with lock:
                calls.append(threading.current_thread().daemon)
            release.wait(3)
            raise socket.gaierror("PRIVATE DNS MESSAGE")

        probes = [d._Probe("worker", host="blocked.example", domain="blocked.example") for _ in range(20)]
        begin = time.monotonic()
        try:
            with patch.object(d, "_build_probes", return_value=(probes, {})), \
                    patch.object(socket, "getaddrinfo", blocked_dns), \
                    patch.multiple(d, RUN_TIMEOUT=.16, ATTEMPT_TIMEOUT=.055):
                for _ in range(3):
                    report = d.run_diagnostics(snapshot(), threading.Event(), lambda _: None)
            self.assertLess(time.monotonic() - begin, 1)
            self.assertLessEqual(len(calls), 4)
            self.assertTrue(calls and all(calls))
            self.assertEqual(report.status, "partial")
        finally:
            release.set()

    def test_failed_probe_logs_only_closed_code_not_exception_content(self):
        async def connect(*_):
            raise OSError("PRIVATE-PASSWORD https://private.example/token")
        with self.assertLogs("tg-diagnostics", logging.INFO) as captured:
            report = self.run_probes([d._Probe("helper")], connect)
        self.assertEqual(report.results[0].error_code, "connection")
        self.assertNotIn("PRIVATE", "\n".join(captured.output))
        self.assertNotIn("private.example", d.format_report(report))

    def test_coverage_partial_is_honest_about_unchecked_candidates(self):
        async def connect(*_):
            return SimpleNamespace(close=AsyncMock(), writer=Mock())
        with patch.object(d, "_build_probes", return_value=([d._Probe("cf")], {"cf": 3})), \
                patch.object(d, "_connect", connect):
            report = d.run_diagnostics(snapshot(), threading.Event(), lambda _: None)
        self.assertEqual(report.status, "partial")
        self.assertIn(d.Coverage("cf", 1, 3), report.coverage)


class ProtocolTest(unittest.IsolatedAsyncioTestCase):
    async def test_transport_options_preserve_production_tls_policy(self):
        for kind, expected_sni in (("direct", None), ("fronted", "sprinthost.ru"), ("worker", None)):
            with patch.object(d.RawWebSocket, "connect", AsyncMock(return_value=Mock())) as connect:
                await d._connect(d._Probe(kind, host="127.0.0.1", domain="kws2.web.telegram.org"), snapshot())
                self.assertTrue(connect.call_args.kwargs["secure"])
                self.assertEqual(connect.call_args.kwargs["sni"], expected_sni)

    async def test_real_tls_ws_valid_identity_and_wrong_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = _make_certificate(Path(tmp), common_name="helper-test.example")
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert, key)
            trusted = ssl.create_default_context(cafile=str(cert))
            for domain, accepted in (("helper-test.example", True), ("kws2.web.telegram.org", False)):
                with self.subTest(domain=domain):
                    requests = []
                    async def peer(reader, writer):
                        try:
                            request = await reader.readuntil(b"\r\n\r\n")
                            requests.append(request)
                            key = next(line.split(b": ", 1)[1] for line in request.split(b"\r\n")
                                if line.startswith(b"Sec-WebSocket-Key: "))
                            accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                            writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                                b"Connection: Upgrade\r\nSec-WebSocket-Protocol: binary\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
                            await writer.drain()
                            await reader.read()
                        except (ConnectionError, asyncio.IncompleteReadError):
                            pass
                        finally:
                            writer.close()
                            await writer.wait_closed()
                    server = await asyncio.start_server(peer, "127.0.0.1", 0, ssl=server_context)
                    port = server.sockets[0].getsockname()[1]
                    real_open = asyncio.open_connection
                    async def local_open(host, incoming_port, **options):
                        return await real_open("127.0.0.1", port, **options)
                    try:
                        with patch("proxy.raw_websocket.asyncio.open_connection", local_open), \
                                patch("proxy.raw_websocket._ssl_ctx", trusted):
                            probe = d._Probe("direct", host="149.154.167.220" if domain.endswith(".telegram.org") else domain, domain=domain)
                            if accepted:
                                connection = await d._attempt(probe, snapshot())
                                await d._close_connection(connection)
                            else:
                                with self.assertRaises(ssl.SSLCertVerificationError):
                                    await d._attempt(probe, snapshot())
                        self.assertEqual(bool(requests), accepted)
                    finally:
                        server.close()
                        await server.wait_closed()

    async def test_real_ws_upgrade_valid_invalid_large_and_stalled(self):
        for case in ("ok", "bad", "large", "slow"):
            with self.subTest(case=case):
                closed = asyncio.Event()

                async def peer(reader, writer):
                    try:
                        request = await reader.readuntil(b"\r\n\r\n")
                        key = next(line.split(b": ", 1)[1] for line in request.split(b"\r\n")
                                   if line.startswith(b"Sec-WebSocket-Key: "))
                        accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                        if case == "slow":
                            await reader.read()
                            return
                        response = (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                            b"Connection: Upgrade\r\nSec-WebSocket-Protocol: binary\r\nSec-WebSocket-Accept: " +
                            (b"invalid" if case == "bad" else accept) + b"\r\n")
                        if case == "large":
                            response += (b"X-Padding: " + b"a" * 100 + b"\r\n") * 400
                        writer.write(response + b"\r\n")
                        await writer.drain()
                        await reader.read()
                    except (ConnectionError, asyncio.IncompleteReadError):
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                        closed.set()

                server = await asyncio.start_server(peer, "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                real_open = asyncio.open_connection

                async def local_open(host, incoming_port, **options):
                    # Only adapt the test's ephemeral loopback port. Production
                    # connector still validates the actual Upgrade bytes.
                    return await real_open("127.0.0.1", port)

                try:
                    with patch("proxy.raw_websocket.asyncio.open_connection", local_open), \
                            patch.object(d, "ATTEMPT_TIMEOUT", .1):
                        probe = d._Probe("direct", host="149.154.167.220", domain="kws2.web.telegram.org")
                        if case == "ok":
                            connection = await d._attempt(probe, snapshot())
                            await d._close_connection(connection)
                        else:
                            with self.assertRaises(TimeoutError if case == "slow" else WsHandshakeError):
                                await d._attempt(probe, snapshot())
                    await asyncio.wait_for(closed.wait(), 1)
                finally:
                    server.close()
                    await server.wait_closed()

    async def test_real_helper_tls_pin_before_credentials_and_ok_no(self):
        from helper_server import read_frame, write_frame
        with tempfile.TemporaryDirectory() as tmp:
            cert, key, fingerprint = _make_certificate(Path(tmp))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            for mode in ("ok", "no", "pin"):
                with self.subTest(mode=mode):
                    seen = []
                    finished = asyncio.Event()

                    async def peer(reader, writer):
                        try:
                            seen.append(await read_frame(reader, 1))
                            seen.append(await read_frame(reader, 1))
                            await write_frame(writer, b"OK" if mode == "ok" else b"NO", 1)
                            await reader.read()
                        except (ConnectionError, asyncio.IncompleteReadError):
                            pass
                        finally:
                            writer.close()
                            await writer.wait_closed()
                            finished.set()

                    server = await asyncio.start_server(peer, "127.0.0.1", 0, ssl=context)
                    active = ProxyConfig(helper_mode="tls-pin", helper_host="127.0.0.1",
                        helper_port=server.sockets[0].getsockname()[1],
                        helper_fingerprint=fingerprint if mode != "pin" else "0" * 64,
                        helper_token="a" * 64)
                    value = d.make_snapshot({}, running=True, active=active)
                    try:
                        probe = d._Probe("helper", host="127.0.0.1", domain="kws2.web.telegram.org")
                        if mode == "ok":
                            connection = await d._attempt(probe, value)
                            self.assertIsInstance(connection, HelperConnection)
                            await d._close_connection(connection)
                        else:
                            with self.assertRaises(PermissionError if mode == "no" else ssl.SSLError):
                                await d._attempt(probe, value)
                        await asyncio.wait_for(finished.wait(), 1)
                        self.assertEqual(seen, [] if mode == "pin" else [b"a" * 64, b"kws2.web.telegram.org"])
                    finally:
                        server.close()
                        await server.wait_closed()

    async def test_stalled_shutdown_is_aborted_after_cleanup_deadline(self):
        writer = Mock(wait_closed=AsyncMock(side_effect=lambda: asyncio.sleep(60)))
        # Use an actual coroutine to model a TLS peer ignoring close_notify.
        async def stalled_close():
            await asyncio.sleep(60)
        connection = SimpleNamespace(writer=writer, close=stalled_close)
        begin = time.monotonic()
        with patch.object(d, "CLEANUP_TIMEOUT", .025):
            await d._close_connection(connection)
        self.assertLess(time.monotonic() - begin, .5)
        writer.transport.abort.assert_called_once()


class ReportTest(unittest.TestCase):
    def test_allowlist_report_never_serializes_raw_labels_or_unknown_error(self):
        report = d.DiagnosticsReport((d.ProbeResult("helper", "PRIVATE-HOST-TOKEN", 2, False,
            "error", "PRIVATE-EXCEPTION", 3),), "partial", "open_routes", "2026-10-24T17:00:00+00:00",
            "1.15.0", 10, (d.Coverage("helper", 0, 1),), "PRIVATE-IDENTITY", True, "Windows 11")
        text = d.format_report(report)
        self.assertNotIn("PRIVATE", text)
        self.assertIn("code=connection", text)
        self.assertIn("transport availability only", text)
        self.assertEqual(text, d.format_report(report))

    def test_staging_version_and_safe_candidate_alias_export(self):
        report = d.DiagnosticsReport((d.ProbeResult("cf", "private.example", 2, None,
            "ok", "", 3, 1),), "complete", "open_telegram", "2026-10-24T17:00:00+00:00",
            "1.15.0-staging.1", 10, (), "", True, "Windows 11", "AMD64")
        text = d.format_report(report)
        self.assertIn("1.15.0-staging.1", text)
        self.assertIn("WebSocket #1 DC2", text)
        self.assertIn("Recommendation: open_telegram", text)
        self.assertIn("architecture=AMD64", text)
        self.assertIn("proxy_running=True", text)
        self.assertNotIn("private.example", text)

    def test_error_codes_are_closed_categories(self):
        cases = ((socket.gaierror("secret"), "dns"), (TimeoutError("secret"), "timeout"),
            (ssl.SSLError("secret"), "tls"), (PermissionError("secret"), "helper_rejected"),
            (WsHandshakeError(403, "secret"), "http_forbidden"),
            (WsHandshakeError(429, "secret"), "http_rate_limited"),
            (WsHandshakeError(302, "secret"), "http_redirect"),
            (WsHandshakeError(101, "secret"), "ws_upgrade"),
            (ConnectionRefusedError("secret"), "refused"))
        for error, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(d._error_code(error), expected)
