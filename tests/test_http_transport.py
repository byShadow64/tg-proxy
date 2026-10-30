"""Bounded HTTP resolver and real loopback connection/response cleanup."""
import http.client
import socket
import ssl
import threading
import time
import unittest
from unittest import mock

from release_tools import github
from proxy import http_transport
from utils import update_check


class HTTPConnectionBoundsTests(unittest.TestCase):
    def test_stalled_resolvers_return_on_deadline_and_never_grow_past_four(self):
        release, finished = threading.Event(), threading.Event()
        count, lock = [0, 0], threading.Lock()
        slots = threading.BoundedSemaphore(4)

        def stuck(*_):
            with lock:
                count[0] += 1
            release.wait(3)
            with lock:
                count[1] += 1
                if count[1] == 4:
                    finished.set()
            return []

        try:
            with mock.patch.object(http_transport, '_DNS_SLOTS', slots), \
                    mock.patch.object(socket, 'getaddrinfo', side_effect=stuck):
                for _ in range(8):
                    started = time.monotonic()
                    with self.assertRaises(TimeoutError):
                        http_transport.create_connection(('synthetic.invalid', 443), deadline=started + .04)
                    self.assertLess(time.monotonic() - started, .5)
                self.assertEqual(count[0], 4)
                self.assertFalse(slots.acquire(blocking=False))
        finally:
            release.set()
            self.assertTrue(finished.wait(2))
        self.assertTrue(slots.acquire(timeout=1))
        slots.release()

    def test_thread_start_and_constructor_failure_release_dns_capacity(self):
        for target in ('threading.Thread', 'threading.Thread.start'):
            with self.subTest(target=target), \
                    mock.patch.object(http_transport, '_DNS_SLOTS', threading.BoundedSemaphore(1)), \
                    mock.patch('proxy.http_transport.' + target, side_effect=RuntimeError('synthetic-private')):
                for _ in range(3):
                    with self.assertRaisesRegex(OSError, '^HTTP resolver could not start$'):
                        http_transport.create_connection(('synthetic.invalid', 443), deadline=time.monotonic() + .2)

    def test_all_address_attempts_share_deadline_and_failed_sockets_close(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port)) for port in range(100)]
        sockets = []

        def make_socket(*_):
            sock = mock.Mock()
            def fail(*_):
                time.sleep(.03)
                raise ConnectionRefusedError('synthetic')
            sock.connect.side_effect = fail
            sockets.append(sock)
            return sock

        with mock.patch.object(socket, 'getaddrinfo', return_value=addresses), \
                mock.patch.object(socket, 'socket', side_effect=make_socket):
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                http_transport.create_connection(('synthetic.invalid', 443), deadline=started + .08)
            self.assertLess(time.monotonic() - started, .4)
        self.assertLessEqual(len(sockets), 3)
        for sock in sockets:
            sock.close.assert_called_once()

    def test_real_loopback_connection_preserves_source_binding_and_timeout(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            with http_transport.create_connection(listener.getsockname(), 1, ('127.0.0.1', 0),
                                                   deadline=time.monotonic() + 2) as client:
                self.assertEqual(client.getsockname()[0], '127.0.0.1')
                self.assertGreater(client.gettimeout(), 0)
                self.assertLessEqual(client.gettimeout(), 1)
                with listener.accept()[0] as peer:
                    peer.sendall(b'ok')
                    self.assertEqual(client.recv(2), b'ok')

    def test_updater_passes_same_deadline_to_dns_and_response_across_redirects(self):
        with mock.patch.object(update_check, 'build_github_opener') as factory, \
                mock.patch.object(update_check, '_response_with_deadline') as response:
            update_check._secure_opener(.25)
        self.assertEqual(factory.call_args.kwargs['connection_deadline'], response.call_args.args[0])
        self.assertIs(factory.call_args.kwargs['response_class'], response.return_value)


class ActionsResponseBoundsTests(unittest.TestCase):
    def test_slow_status_headers_and_chunk_framing_obey_absolute_deadline(self):
        # Prepare TLS trust and a connected loopback peer before the short
        # response-parser budget. Separate tests cover bounded DNS/TCP setup;
        # this one must reach the real status/header/chunk parser every time.
        context = ssl.create_default_context()
        for prefix in (b'', b'HTTP/1.1 200 OK\r\nX-Test: ',
                       b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;'):
            with self.subTest(prefix=prefix), socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                listener.settimeout(2)
                accepted, request_received, closed, stop = (threading.Event() for _ in range(4))
                peers = []

                def serve():
                    try:
                        with listener.accept()[0] as peer:
                            peers.append(peer)
                            accepted.set()
                            peer.settimeout(1)
                            data = b''
                            while b'\r\n\r\n' not in data:
                                chunk = peer.recv(4096)
                                if not chunk:
                                    return  # EOF before a complete request must not spin.
                                data += chunk
                            request_received.set()
                            peer.sendall(prefix)
                            for _ in range(100):
                                peer.sendall(b'a')
                                if stop.wait(.015):
                                    return
                    except OSError:
                        pass
                    finally:
                        closed.set()

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                connection = http.client.HTTPConnection(*listener.getsockname(), timeout=.3)
                connections = []
                def factory(host, **kwargs):
                    connections.append(connection)
                    return connection
                client = github.GitHubClient('SYNTHETIC-TOKEN', _connection_factory=factory)
                try:
                    connection.connect()
                    self.assertTrue(accepted.wait(2))
                    started = time.monotonic()
                    with mock.patch('release_tools.github.ssl.create_default_context', return_value=context):
                        with self.assertRaisesRegex(github.GitHubError, 'timeout'):
                            client._request('GET', 'https://api.github.com/user', deadline_seconds=.15)
                    self.assertLess(time.monotonic() - started, .75)
                    self.assertTrue(request_received.is_set())
                    self.assertIsNone(connections[0].sock)
                    self.assertTrue(closed.wait(2))
                finally:
                    stop.set()
                    connection.close()
                    for peer in peers:
                        try:
                            peer.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    listener.close()
                    worker.join(2)
                    self.assertFalse(worker.is_alive())

    def test_actions_dns_failure_is_bounded_and_does_not_send_authorization(self):
        # Loading the Windows trust store may itself exhaust the short request
        # budget. Prepare it first so this test actually exercises stalled DNS.
        context = ssl.create_default_context()
        release, started, finished, returned = (threading.Event() for _ in range(4))
        errors, elapsed = [], []

        def resolver(*_):
            started.set()
            try:
                if not release.wait(2):
                    raise AssertionError("Fixture resolver was not released")
                return []
            finally:
                finished.set()

        cancel = threading.Event()
        client = github.GitHubClient('SYNTHETIC-TOKEN', cancel=cancel)

        def request():
            began = time.monotonic()
            try:
                client._request('GET', 'https://api.github.com/user', deadline_seconds=.08)
            except BaseException as exc:
                errors.append(exc)
            finally:
                elapsed.append(time.monotonic() - began)
                returned.set()

        worker = threading.Thread(target=request, daemon=True)
        with mock.patch.object(github.ssl, 'create_default_context', return_value=context), \
                mock.patch.object(socket, 'getaddrinfo', side_effect=resolver), \
                mock.patch.object(socket, 'socket') as sockets:
            try:
                worker.start()
                self.assertTrue(started.wait(1), "The stalled DNS resolver was not entered")
                self.assertTrue(returned.wait(.5), "The request exceeded its bounded wait")
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], github.GitHubError)
                self.assertRegex(str(errors[0]), 'timeout')
                self.assertLess(elapsed[0], .5)
                sockets.assert_not_called()
            finally:
                cancel.set()
                release.set()
                worker.join(2)
                self.assertFalse(worker.is_alive())
                if started.is_set():
                    self.assertTrue(finished.wait(2))


if __name__ == '__main__':
    unittest.main()
