import asyncio
import base64
import hashlib
import logging
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from proxy.config import proxy_config
from proxy.balancer import balancer
from tests.test_helper_protocol import _make_certificate
from ui import connectivity as ui
from utils import connection_diagnostics as d, route_diagnostics as r


def cases(count=1):
    return [r.RouteCase(i // 6, i % 6 + 1, 'private-host.example',
                        'private-host.example', 'private-host.example', '/apiws') for i in range(count)]


class RouteRunnerTest(unittest.TestCase):
    def test_failed_dns_thread_start_releases_its_slot(self):
        loop = asyncio.new_event_loop()
        resolver = d._DaemonResolver(loop)
        resolver.slots = threading.BoundedSemaphore(1)
        try:
            with patch.object(d.threading.Thread, 'start', side_effect=RuntimeError('no thread capacity')):
                with self.assertRaises(RuntimeError):
                    loop.run_until_complete(resolver.getaddrinfo('example.org', 443))
            self.assertTrue(resolver.slots.acquire(blocking=False))
            resolver.slots.release()
        finally:
            loop.close()

    def test_four_parallel_and_all_connections_closed_without_config_or_pool_changes(self):
        current, peak, closed = 0, 0, []
        config = dict(vars(proxy_config))
        domains = tuple(balancer.domains)

        class Connection:
            def __init__(self):
                self.writer = SimpleNamespace()
            async def close(self):
                closed.append(True)

        async def connect(case, secure):
            nonlocal current, peak
            current += 1
            peak = max(current, peak)
            try:
                await asyncio.sleep(.01)
                return Connection()
            finally:
                current -= 1

        with patch.object(r, '_connect_case', connect):
            result = r.run_route_checks(cases(18))
        self.assertEqual(peak, 4)
        self.assertEqual(len(closed), 18)
        self.assertTrue(all(v.status == 'ok' for v in result))
        self.assertEqual(vars(proxy_config), config)
        self.assertEqual(tuple(balancer.domains), domains)

    def test_cancel_deadline_and_busy_do_not_retain_tasks_or_raw_exceptions(self):
        async def stuck(*_):
            await asyncio.sleep(60)
        for mode in ('cancel', 'deadline'):
            with self.subTest(mode=mode):
                cancel = threading.Event()
                timer = threading.Timer(.04, cancel.set) if mode == 'cancel' else None
                if timer:
                    timer.start()
                begin = time.monotonic()
                with patch.object(r, '_connect_case', stuck), patch.object(r, 'RUN_TIMEOUT', .06):
                    result = r.run_route_checks(cases(18), cancel=cancel)
                self.assertLess(time.monotonic() - begin, .5)
                self.assertEqual({v.status for v in result}, {'cancelled' if timer else 'incomplete'})
                if timer:
                    timer.join()
        with r._RUN_LOCK:
            self.assertEqual(r.run_route_checks(cases())[0].error_code, 'busy')
        async def rejected(*_):
            raise OSError('SYNTHETIC-SECRET private-server.example C:/private/profile')
        with patch.object(r, '_connect_case', rejected), self.assertLogs('tg-diagnostics', logging.INFO) as logs:
            result = r.run_route_checks(cases())
        self.assertEqual(result[0].error_code, 'connection')
        self.assertNotIn('SYNTHETIC', str(result) + str(logs.output))
        self.assertNotIn('private-server', str(result) + str(logs.output))
        self.assertNotIn('private-host', repr(cases()[0]))

    def test_stuck_dns_has_a_bounded_run_and_daemon_shutdown(self):
        entered, release = threading.Event(), threading.Event()
        real = socket.getaddrinfo
        def resolver(*args, **kwargs):
            entered.set()
            release.wait(2)
            return real('127.0.0.1', 1, **kwargs)
        try:
            begin = time.monotonic()
            with patch.object(d.socket, 'getaddrinfo', resolver), patch.object(r, 'RUN_TIMEOUT', .075):
                values = r.run_route_checks(cases(4))
            self.assertTrue(entered.is_set())
            self.assertLess(time.monotonic() - begin, .5)
            self.assertTrue(all(v.status == 'incomplete' for v in values))
        finally:
            release.set()

    def test_domain_cap_is_visible_and_worker_targets_use_production_catalog(self):
        captured = []
        def check(probes, **kwargs):
            captured.extend(probes)
            return tuple(r.RouteResult(p.candidate, p.dc, 'ok') for p in probes)
        with patch.object(ui, 'run_route_checks', check):
            values = ui.run_cfworker_multi_test([f'worker{i}.example' for i in range(8)])
        self.assertEqual(len(captured), 18)
        self.assertEqual((values.tested, values.total), (3, 8))
        self.assertIn('3', ui._scope_note(values))
        self.assertEqual(captured[0].path, '/apiws?dst=149.154.175.50&dc=1')


class RouteTransportTest(unittest.IsolatedAsyncioTestCase):
    async def test_real_http_status_challenge_size_slow_and_success(self):
        for mode in ('ok', 'fake101', 'challenge', 'headers', 'slow', 'forbidden'):
            with self.subTest(mode=mode):
                closed = asyncio.Event()
                async def peer(reader, writer):
                    try:
                        request = await reader.readuntil(b'\r\n\r\n')
                        key = next(line.split(b': ', 1)[1] for line in request.split(b'\r\n')
                                   if line.startswith(b'Sec-WebSocket-Key: '))
                        accept = base64.b64encode(hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
                        if mode == 'slow':
                            await reader.read()
                            return
                        if mode == 'fake101':
                            response = b'HTTP/1.1 200 Status-101\r\n\r\n'
                        elif mode == 'forbidden':
                            response = b'HTTP/1.1 403 SYNTHETIC-SECRET\r\n\r\n'
                        else:
                            response = (b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                                b'Sec-WebSocket-Protocol: binary\r\nSec-WebSocket-Accept: ' +
                                (b'wrong' if mode == 'challenge' else accept) + b'\r\n')
                            if mode == 'headers':
                                response += (b'X-Fill: ' + b'a' * 100 + b'\r\n') * 400
                            response += b'\r\n'
                        writer.write(response)
                        await writer.drain()
                        await reader.read()
                    except (ConnectionError, asyncio.IncompleteReadError):
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                        closed.set()
                server = await asyncio.start_server(peer, '127.0.0.1', 0)
                port = server.sockets[0].getsockname()[1]
                real = asyncio.open_connection
                async def local(*args, **kwargs):
                    return await real('127.0.0.1', port)
                try:
                    with patch('proxy.raw_websocket.asyncio.open_connection', local), patch.object(d, 'ATTEMPT_TIMEOUT', .08):
                        result = (await r._run(cases(), False, threading.Event()))[0]
                    expected = {'ok': '', 'fake101': 'http_error', 'challenge': 'ws_upgrade',
                                'headers': 'ws_upgrade', 'slow': 'timeout', 'forbidden': 'http_forbidden'}[mode]
                    self.assertEqual(result.error_code, expected)
                    self.assertEqual(result.status, 'ok' if mode == 'ok' else 'error')
                    await asyncio.wait_for(closed.wait(), 1)
                finally:
                    server.close()
                    await server.wait_closed()

    async def test_real_tls_rejection_does_not_attempt_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, key, _ = _make_certificate(Path(tmp))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            async def peer(reader, writer):
                writer.close()
                await writer.wait_closed()
            server = await asyncio.start_server(peer, '127.0.0.1', 0, ssl=context)
            port = server.sockets[0].getsockname()[1]
            real = asyncio.open_connection
            attempts = []
            async def local(host, incoming_port, **kwargs):
                attempts.append((incoming_port, kwargs.get('ssl') is not None))
                return await real('127.0.0.1', port, **kwargs)
            try:
                with patch('proxy.raw_websocket.asyncio.open_connection', local):
                    result = (await r._run(cases(), True, threading.Event()))[0]
                self.assertEqual(result.error_code, 'tls')
                self.assertEqual(attempts, [(443, True)])
            finally:
                server.close()
                await server.wait_closed()
