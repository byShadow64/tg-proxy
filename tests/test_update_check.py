import hashlib
import io
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from http.client import HTTPResponse, IncompleteRead
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError, URLError

from utils import update_check
from utils.update_check import _extract_assets, _parse_version_tuple, _version_gt

PAYLOAD = b'payload'
DIGEST = 'sha256:' + hashlib.sha256(PAYLOAD).hexdigest()


class ParseVersionTupleTest(unittest.TestCase):
    def test_plain_and_prefixed_versions(self):
        self.assertEqual(_parse_version_tuple('1.9.1'), (1, 9, 1))
        self.assertEqual(_parse_version_tuple('v1.9.1'), (1, 9, 1))
        self.assertEqual(_parse_version_tuple(' V2.0 '), (2, 0))

    def test_trailing_suffixes_are_truncated_to_digits(self):
        self.assertEqual(_parse_version_tuple('1.9.1rc2'), (1, 9, 1))
        self.assertEqual(_parse_version_tuple('1.9.1-beta'), (1, 9, 1))

    def test_empty_and_non_numeric_segments(self):
        self.assertEqual(_parse_version_tuple(''), (0,))
        self.assertEqual(_parse_version_tuple(None), (0,))
        self.assertEqual(_parse_version_tuple('1.x.3'), (1, 0, 3))


class VersionGtTest(unittest.TestCase):
    def test_newer_versions(self):
        self.assertTrue(_version_gt('1.9.2', '1.9.1'))
        self.assertTrue(_version_gt('1.10.0', '1.9.9'))
        self.assertTrue(_version_gt('2.0', '1.9.9'))

    def test_equal_and_older_versions(self):
        self.assertFalse(_version_gt('1.9.1', '1.9.1'))
        self.assertFalse(_version_gt('1.9.1', '1.9.2'))
        self.assertFalse(_version_gt('1.9', '1.9.0'))

    def test_shorter_version_is_padded_with_zeros(self):
        self.assertTrue(_version_gt('1.9.1', '1.9'))
        self.assertFalse(_version_gt('1.9', '1.9.1'))


class ExtractAssetsTest(unittest.TestCase):
    def test_keeps_name_url_and_digest(self):
        data = {'assets': [{
            'name': 'TgWsProxy_windows.exe',
            'browser_download_url': 'https://example.invalid/a.exe',
            'digest': 'sha256:abc',
        }]}
        self.assertEqual(_extract_assets(data), [{
            'name': 'TgWsProxy_windows.exe',
            'url': 'https://example.invalid/a.exe',
            'digest': 'sha256:abc',
        }])

    def test_drops_entries_without_name_or_url(self):
        data = {'assets': [
            {'name': 'a.exe'},
            {'browser_download_url': 'https://example.invalid/b.exe'},
        ]}
        self.assertEqual(_extract_assets(data), [])

    def test_missing_digest_becomes_empty_string(self):
        data = {'assets': [{
            'name': 'a.exe', 'browser_download_url': 'https://example.invalid/a.exe',
        }]}
        self.assertEqual(_extract_assets(data)[0]['digest'], '')

    def test_empty_input(self):
        self.assertEqual(_extract_assets(None), [])
        self.assertEqual(_extract_assets({}), [])


class _Response(io.BytesIO):
    def __init__(self, body, content_length='auto'):
        super().__init__(body)
        if content_length == 'auto':
            content_length = len(body)
        self.headers = {} if content_length is None else {
            'Content-Length': str(content_length),
        }

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _opener(response):
    opener = mock.Mock()
    opener.open.return_value = response
    return mock.Mock(return_value=opener)


class DownloadAssetTest(unittest.TestCase):
    def _download(self, response, digest=DIGEST):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(update_check, 'build_github_opener', _opener(response)):
                path = update_check.download_asset(
                    'https://example.invalid/a', Path(tmp), suffix='.bin', digest=digest,
                )
            try:
                return path.read_bytes(), sorted(p.name for p in Path(tmp).iterdir())
            finally:
                path.unlink(missing_ok=True)

    def test_complete_download_is_kept(self):
        body, files = self._download(_Response(b'payload'))
        self.assertEqual(body, b'payload')
        self.assertEqual(len(files), 1)

    def test_matching_digest_is_accepted(self):
        digest = 'sha256:' + hashlib.sha256(b'payload').hexdigest()
        body, _ = self._download(_Response(b'payload'), digest=digest)
        self.assertEqual(body, b'payload')

    def test_invalid_or_missing_digest_is_rejected_before_any_download(self):
        for digest in ('', None, 123, 'md5:whatever', 'sha256:ab', 'sha256:' + 'z' * 64):
            with self.subTest(digest=digest), tempfile.TemporaryDirectory() as tmp:
                with mock.patch.object(update_check, 'build_github_opener') as opener:
                    with self.assertRaises(ValueError):
                        update_check.download_asset('https://example.invalid/a', Path(tmp), digest=digest)
                opener.assert_not_called()
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_truncated_download_raises_and_leaves_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            resp = _Response(b'pay', content_length=None)
            with mock.patch.object(update_check, 'build_github_opener', _opener(resp)):
                with self.assertRaises(OSError):
                    update_check.download_asset(
                        'https://example.invalid/a', Path(tmp), suffix='.bin', digest=DIGEST,
                    )
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_digest_mismatch_raises_and_leaves_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            resp = _Response(b'payload')
            with mock.patch.object(update_check, 'build_github_opener', _opener(resp)):
                with self.assertRaises(OSError):
                    update_check.download_asset(
                        'https://example.invalid/a', Path(tmp),
                        suffix='.bin', digest='sha256:' + '0' * 64,
                    )
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_missing_content_length_is_tolerated(self):
        body, _ = self._download(_Response(b'payload', content_length=None))
        self.assertEqual(body, b'payload')

    def test_same_length_corruption_is_rejected(self):
        with self.assertRaisesRegex(OSError, 'SHA-256'):
            self._download(_Response(b'payloae'))

    def test_uppercase_checksum_is_accepted(self):
        body, _ = self._download(_Response(PAYLOAD), digest=DIGEST.upper())
        self.assertEqual(body, PAYLOAD)

    def test_stream_failure_removes_partial_file(self):
        for error in (TimeoutError('read timed out'), IncompleteRead(b'pay', 4)):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as tmp:
                response = mock.MagicMock()
                response.__enter__.return_value = response
                response.geturl.return_value = 'https://example.invalid/a'
                response.read1.side_effect = [b'pay', error]
                with mock.patch.object(update_check, 'build_github_opener', _opener(response)):
                    with self.assertRaises(type(error)):
                        update_check.download_asset('https://example.invalid/a', Path(tmp), digest=DIGEST)
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_hash_covers_every_chunk_and_read_timeout_is_set(self):
        body = PAYLOAD * 20000
        opener = _opener(_Response(body))
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(update_check, 'build_github_opener', opener):
                path = update_check.download_asset(
                    'https://example.invalid/a', Path(tmp),
                    digest='sha256:' + hashlib.sha256(body).hexdigest(), timeout=7,
                )
            self.assertEqual(path.read_bytes(), body)
        opener.return_value.open.assert_called_once_with('https://example.invalid/a', timeout=7)


class FindAssetTest(unittest.TestCase):
    def test_returns_asset_with_digest(self):
        assets = [{'name': 'a.deb', 'url': 'https://example.invalid/a.deb', 'digest': DIGEST}]
        with mock.patch.dict(update_check._state, {'assets': assets}):
            self.assertEqual(update_check.find_asset('a.deb'), assets[0])
            self.assertIsNone(update_check.find_asset('b.deb'))

    def test_ignores_asset_without_url(self):
        with mock.patch.dict(update_check._state, {'assets': [{'name': 'a.deb', 'url': ''}]}):
            self.assertIsNone(update_check.find_asset('a.deb'))

    def test_assets_without_a_valid_checksum_require_manual_installation(self):
        for digest in ('', 'sha256:ab', 'md5:' + '0' * 32):
            asset = {'name': 'a.exe', 'url': 'https://example.invalid/a.exe', 'digest': digest}
            with self.subTest(digest=digest), mock.patch.dict(update_check._state, {'assets': [asset]}):
                self.assertIsNone(update_check.find_asset('a.exe'))

    def test_old_or_equal_version_metadata_cannot_be_installed(self):
        for version in ('1.13.0', '1.14.0', '1.14.0-beta'):
            asset = {'name': 'app.exe', 'url': 'https://example.invalid/app.exe', 'digest': DIGEST,
                     'version': version, 'current_version': '1.14.0'}
            with self.subTest(version=version), mock.patch.dict(update_check._state, {'assets': [asset]}):
                self.assertIsNone(update_check.find_asset('app.exe'))


class BackupCheckTest(unittest.TestCase):
    def setUp(self):
        self.stack = __import__('contextlib').ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(update_check, '_state', update_check.get_status()))
        self.stack.enter_context(mock.patch.object(update_check, '_compatible_asset_names', return_value={'TgWsProxy_windows.exe'}))
        self.stack.enter_context(mock.patch.object(update_check, 'UPDATE_MANIFEST_URL', 'https://backup.invalid/latest.json'))
        self.primary = self.stack.enter_context(mock.patch.object(update_check, 'fetch_latest_release'))
        self.backup = self.stack.enter_context(mock.patch.object(update_check, 'fetch_backup_release'))

    def release(self, version='1.14.0', digest=DIGEST, name='TgWsProxy_windows.exe'):
        return {'tag_name': version, 'html_url': 'https://github.com/example/releases/' + version,
                'assets': [{'name': name, 'browser_download_url': 'https://example.invalid/a.exe',
                            'size': len(PAYLOAD), 'digest': digest}]}

    def fallback(self, version='1.14.0'):
        return {'latest': version, 'html_url': 'https://backup.invalid/releases/' + version,
                'source': 'backup', 'assets': [{'name': 'TgWsProxy_windows.exe',
                'url': 'https://backup.invalid/a.exe', 'digest': DIGEST, 'size': len(PAYLOAD),
                'version': version, 'source': 'backup'}]}

    def test_healthy_newer_compatible_github_release_is_preferred_without_backup_request(self):
        self.primary.return_value = self.release()
        update_check.run_check('1.13.0')
        self.backup.assert_not_called()
        status = update_check.get_status()
        self.assertEqual(status['source'], 'github')
        self.assertTrue(status['has_update'])
        asset = update_check.find_asset('TgWsProxy_windows.exe')
        self.assertEqual((asset['version'], asset['size'], asset['source']), ('1.14.0', len(PAYLOAD), 'github'))

    def test_old_or_incompatible_primary_cannot_hide_a_new_backup_release(self):
        for release in (self.release('1.13.0'), self.release(digest=''), self.release(name='unrelated.exe')):
            with self.subTest(release=release):
                self.primary.return_value = release
                self.backup.return_value = self.fallback('1.15.0')
                update_check.run_check('1.13.0')
                status = update_check.get_status()
                self.assertEqual((status['source'], status['latest']), ('backup', '1.15.0'))
                self.assertTrue(status['has_update'])
                self.assertIsNone(status['error'])
                self.assertEqual(update_check.find_asset('TgWsProxy_windows.exe')['size'], len(PAYLOAD))

    def test_equal_version_backup_replaces_only_an_uninstallable_github_release(self):
        for release in (self.release(digest=''), self.release(name='unrelated.exe'),
                        {**self.release(), 'assets': []}):
            with self.subTest(release=release):
                self.primary.return_value = release
                self.backup.return_value = self.fallback('1.14.0')
                update_check.run_check('1.13.0')
                status = update_check.get_status()
                self.assertEqual((status['source'], status['latest']), ('backup', '1.14.0'))
                asset = update_check.find_asset('TgWsProxy_windows.exe')
                self.assertEqual(asset['url'], 'https://backup.invalid/a.exe')
                self.assertEqual((asset['version'], asset['size']), ('1.14.0', len(PAYLOAD)))

    def test_equal_version_backup_without_compatible_asset_cannot_replace_github(self):
        self.primary.return_value = self.release(digest='')
        backup = self.fallback('1.14.0')
        backup['assets'][0]['name'] = 'TgWsProxy_helper.zip'
        self.backup.return_value = backup
        update_check.run_check('1.13.0')
        self.assertEqual(update_check.get_status()['source'], 'github')
        self.assertIsNone(update_check.find_asset('TgWsProxy_windows.exe'))

    def test_older_backup_does_not_replace_a_newer_uninstallable_github_release(self):
        self.primary.return_value = self.release('1.15.0', digest='')
        self.backup.return_value = self.fallback('1.14.0')
        update_check.run_check('1.13.0')
        status = update_check.get_status()
        self.assertEqual((status['source'], status['latest']), ('github', '1.15.0'))
        self.assertIsNone(update_check.find_asset('TgWsProxy_windows.exe'))

    def test_404_offline_or_invalid_github_can_fall_back(self):
        for error in (HTTPError('https://github.com', 404, 'missing', {}, None), URLError('offline'), ValueError('invalid')):
            with self.subTest(error=error):
                self.primary.side_effect = error
                self.backup.return_value = self.fallback()
                update_check.run_check('1.13.0')
                status = update_check.get_status()
                self.assertEqual(status['source'], 'backup')
                self.assertTrue(status['has_update'])
                self.assertIsNone(status['http_status'])

    def test_invalid_backup_cannot_replace_valid_github_or_claim_update_after_both_fail(self):
        self.primary.return_value = self.release('1.13.0')
        self.backup.side_effect = ValueError('bad signature')
        update_check.run_check('1.13.0')
        status = update_check.get_status()
        self.assertEqual(status['source'], 'github')
        self.assertFalse(status['has_update'])
        self.assertIsNone(status['error'])
        self.primary.side_effect = URLError('offline')
        update_check.run_check('1.13.0')
        status = update_check.get_status()
        self.assertIsNone(status['source'])
        self.assertTrue(status['error'])
        self.assertEqual(status['assets'], [])

    def test_backup_never_promotes_old_or_equal_release(self):
        self.primary.side_effect = URLError('offline')
        for version in ('1.13.0', '1.14.0', '1.14.0-beta'):
            with self.subTest(version=version):
                self.backup.return_value = self.fallback(version)
                update_check.run_check('1.14.0')
                self.assertFalse(update_check.get_status()['has_update'])
                self.assertIsNone(update_check.find_asset('TgWsProxy_windows.exe'))

    def test_explicit_server_url_override_and_disable(self):
        self.primary.return_value = self.release('1.13.0')
        self.backup.return_value = self.fallback()
        update_check.run_check('1.13.0', server_url='https://override.invalid/latest.json')
        self.backup.assert_called_once_with('https://override.invalid/latest.json')
        self.backup.reset_mock()
        update_check.run_check('1.13.0', server_url='')
        self.backup.assert_not_called()


class BackupDownloadTest(unittest.TestCase):
    def setUp(self):
        self.asset = {'name': 'TgWsProxy_windows.exe', 'url': 'https://github.com/release/a.exe',
                      'digest': DIGEST, 'size': len(PAYLOAD), 'source': 'github', 'version': '1.14.0',
                      'current_version': '1.13.0', 'manifest_url': 'https://backup.invalid/latest.json'}

    def fallback(self, version='1.14.0', name='TgWsProxy_windows.exe'):
        return {'latest': version, 'assets': [{'name': name, 'url': 'https://backup.invalid/a.exe',
                'digest': 'sha256:' + 'b' * 64, 'size': 999, 'version': version, 'source': 'backup'}]}

    def test_failed_primary_download_returns_actual_signed_candidate_for_reverification(self):
        with mock.patch.object(update_check, 'download_asset', side_effect=[OSError('offline'), Path('verified')]) as download, \
                mock.patch.object(update_check, 'fetch_backup_release', return_value=self.fallback('1.15.0')) as backup:
            path, actual = update_check.download_release_asset(self.asset, Path('unused'))
        backup.assert_called_once_with(self.asset['manifest_url'])
        self.assertEqual(path, Path('verified'))
        self.assertEqual((actual['version'], actual['source'], actual['size']), ('1.15.0', 'backup', 999))
        self.assertEqual(download.call_args.kwargs['digest'], actual['digest'])
        self.assertEqual(download.call_args.kwargs['size'], 999)
        self.assertEqual(self.asset['source'], 'github')

    def test_fallback_never_downgrades_requested_candidate_or_changes_architecture(self):
        for fallback in (self.fallback('1.13.9'), self.fallback('1.14.0-beta'), self.fallback(name='TgWsProxy_helper.zip')):
            with self.subTest(fallback=fallback), \
                    mock.patch.object(update_check, 'download_asset', side_effect=OSError('offline')) as download, \
                    mock.patch.object(update_check, 'fetch_backup_release', return_value=fallback):
                with self.assertRaises(ValueError):
                    update_check.download_release_asset(self.asset, Path('unused'))
                self.assertEqual(download.call_count, 1)

    def test_successful_github_or_failed_backup_has_no_further_retry(self):
        with mock.patch.object(update_check, 'download_asset', return_value=Path('verified')), \
                mock.patch.object(update_check, 'fetch_backup_release') as backup:
            _, asset = update_check.download_release_asset(self.asset, Path('unused'))
            self.assertEqual(asset['source'], 'github')
            backup.assert_not_called()

    def test_equal_or_older_initial_candidate_is_rejected_before_downloading(self):
        for version in ('1.13.0', '1.12.9'):
            asset = {**self.asset, 'version': version}
            with self.subTest(version=version), mock.patch.object(update_check, 'download_asset') as download:
                with self.assertRaises(ValueError):
                    update_check.download_release_asset(asset, Path('unused'))
                download.assert_not_called()
        asset = {**self.asset, 'source': 'backup'}
        with mock.patch.object(update_check, 'download_asset', side_effect=OSError('offline')), \
                mock.patch.object(update_check, 'fetch_backup_release') as backup:
            with self.assertRaises(OSError):
                update_check.download_release_asset(asset, Path('unused'))
            backup.assert_not_called()


class SecureDownloadTest(unittest.TestCase):
    def test_redirect_bodies_are_never_allocated_or_read_and_all_paths_close_them(self):
        from urllib.request import Request

        for code in (301, 302, 303, 307, 308):
            for target in ('https://next.invalid/a', 'http://insecure.invalid/a', 'file:///untrusted'):
                with self.subTest(code=code, target=target):
                    incoming, outgoing = socket.socketpair()
                    incoming.settimeout(.5)
                    outgoing.sendall((f'HTTP/1.1 {code} Redirect\r\nLocation: {target}\r\n'
                                      'Content-Length: 1073741824\r\n\r\n').encode())
                    response = update_check._response_with_deadline(time.monotonic() + 60)(incoming)
                    try:
                        response.begin()
                        request = Request('https://start.invalid/a')
                        request.timeout = 1
                        handler = update_check._HTTPSOnlyRedirect()
                        handler.parent = mock.Mock()
                        callback = getattr(handler, f'http_error_{code}')
                        # A huge redirect must not reach the allocation/read
                        # path even when its body has not arrived at all.
                        with mock.patch.object(response, '_safe_read', side_effect=AssertionError('unbounded drain')) as read:
                            if target.startswith('https://'):
                                result = callback(request, response, code, 'Redirect', response.headers)
                                self.assertIs(result, handler.parent.open.return_value)
                                self.assertEqual(handler.parent.open.call_args.args[0].full_url, target)
                            else:
                                with self.assertRaises((ValueError, HTTPError)):
                                    callback(request, response, code, 'Redirect', response.headers)
                                handler.parent.open.assert_not_called()
                            read.assert_not_called()
                        self.assertTrue(response.closed)
                        self.assertTrue(response._deadline_timer.finished.is_set())
                    finally:
                        response.close()
                        incoming.close()
                        outgoing.close()
                        response._deadline_timer.join(timeout=1)
                    self.assertFalse(response._deadline_timer.is_alive())

    def test_deadline_interrupts_a_real_tls_response_after_connection_detaches(self):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(minutes=1))
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                       .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        with tempfile.TemporaryDirectory() as directory:
            cert_path, key_path = Path(directory) / 'test.pem', Path(directory) / 'test-key.pem'
            cert_path.write_bytes(certificate)
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                  serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert_path, key_path)
            client_context = ssl.create_default_context(cadata=certificate.decode('ascii'))
            incoming, outgoing = socket.socketpair()
            incoming.settimeout(1)
            outgoing.settimeout(1)
            stopped = threading.Event()

            def server():
                try:
                    with server_context.wrap_socket(outgoing, server_side=True) as secure:
                        secure.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n')
                        for _ in range(100):
                            secure.sendall(b'1')
                            if stopped.wait(.02):
                                return
                except OSError:
                    pass

            worker = threading.Thread(target=server)
            worker.start()
            response = None
            try:
                secure = client_context.wrap_socket(incoming, server_hostname='localhost')
                started = time.monotonic()
                response = update_check._response_with_deadline(started + .15)(secure)
                secure.close()
                with response, self.assertRaises(TimeoutError):
                    response.begin()
                    response.read1(65536)
                self.assertLess(time.monotonic() - started, 1.0)
            finally:
                stopped.set()
                if response is not None:
                    response.close()
                    response._deadline_timer.join(timeout=1)
                incoming.close()
                outgoing.close()
                worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(response._deadline_timer.is_alive())

    def test_response_deadline_interrupts_slow_status_headers_and_chunk_framing(self):
        cases = (
            ('status', b'HTTP/1.1 ', False),
            ('header', b'HTTP/1.1 200 OK\r\nX-Slow: ', False),
            ('chunk-size', b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n', True),
            ('chunk-trailer', b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Slow: ', True),
        )
        for name, prefix, read_body in cases:
            with self.subTest(name=name):
                incoming, outgoing = socket.socketpair()
                incoming.settimeout(.5)
                stopped = threading.Event()

                def server():
                    try:
                        outgoing.sendall(prefix)
                        for _ in range(100):
                            outgoing.sendall(b'1')
                            if stopped.wait(.02):
                                return
                    except OSError:
                        pass

                worker = threading.Thread(target=server)
                worker.start()
                started = time.monotonic()
                response = update_check._response_with_deadline(started + .12)(incoming)
                # urllib closes the connection's own handle after headers. Its
                # response file still owns the socket; shutdown must work here.
                if read_body:
                    incoming.close()
                try:
                    with response, self.assertRaises(TimeoutError):
                        response.begin()
                        if read_body:
                            response.read1(65536)
                    self.assertLess(time.monotonic() - started, 1.0)
                finally:
                    stopped.set()
                    response.close()
                    incoming.close()
                    outgoing.close()
                    worker.join(timeout=2)
                    response._deadline_timer.join(timeout=1)
                self.assertFalse(worker.is_alive())
                self.assertFalse(response._deadline_timer.is_alive())

    def test_normal_response_and_http_error_cancel_the_socket_watchdog(self):
        for status in (200, 404):
            with self.subTest(status=status):
                incoming, outgoing = socket.socketpair()
                incoming.settimeout(.5)
                outgoing.sendall(f'HTTP/1.1 {status} Result\r\nContent-Length: 3\r\n\r\nabc'.encode())
                response = update_check._response_with_deadline(time.monotonic() + 60)(incoming)
                try:
                    response.begin()
                    if status == 200:
                        with response:
                            self.assertEqual(response.read1(3), b'abc')
                    else:
                        error = HTTPError('https://example.invalid/a', 404, 'missing', {}, response)
                        opener = mock.Mock()
                        opener.open.side_effect = error
                        with mock.patch.object(update_check, '_secure_opener', return_value=opener), \
                                self.assertRaises(HTTPError):
                            update_check._open_response('https://example.invalid/a', timeout=1, response_timeout=1)
                    self.assertTrue(response.closed or response.isclosed())
                    self.assertTrue(response._deadline_timer.finished.is_set())
                finally:
                    response.close()
                    incoming.close()
                    outgoing.close()
                    response._deadline_timer.join(timeout=1)
                self.assertFalse(response._deadline_timer.is_alive())

    def test_pinned_and_default_https_connections_use_the_response_policy(self):
        from http.client import HTTPSConnection
        from urllib.request import HTTPSHandler, Request
        from proxy.utils import _PinnedHTTPSHandler

        policy = update_check._response_with_deadline(time.monotonic() + 1)
        handler = _PinnedHTTPSHandler(response_class=policy)
        for url in ('https://api.github.com/releases', 'https://release-assets.githubusercontent.com/asset'):
            with self.subTest(url=url), mock.patch.object(HTTPSHandler, 'do_open') as base:
                handler.https_open(Request(url))
                connection = base.call_args.args[0]
                self.assertTrue(issubclass(connection, HTTPSConnection))
                self.assertIs(connection.response_class, policy)

    def test_trickling_http_body_cannot_hide_inside_one_large_read(self):
        # A real HTTPResponse reproduces the old read(65536) behaviour: each
        # byte arrives before the socket timeout, but the full body takes 2s.
        incoming, outgoing = socket.socketpair()
        incoming.settimeout(.5)
        stopped = threading.Event()

        def server():
            try:
                outgoing.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n')
                for _ in range(100):
                    outgoing.sendall(b'x')
                    if stopped.wait(.02):
                        return
            except OSError:
                pass

        worker = threading.Thread(target=server)
        worker.start()
        response = HTTPResponse(incoming)
        try:
            response.begin()
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                update_check._read_bounded(response, 1024, timeout=.12)
            self.assertLess(time.monotonic() - started, 1.0)
        finally:
            stopped.set()
            response.close()
            incoming.close()
            outgoing.close()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())

    def test_download_checks_deadline_between_partial_body_packets(self):
        response = _Response(PAYLOAD)
        response.read = mock.Mock(side_effect=AssertionError('full-block read can hang'))
        original = response.read1
        response.read1 = mock.Mock(side_effect=lambda size: original(1))
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(update_check, 'build_github_opener', _opener(response)), \
                mock.patch.object(update_check.time, 'monotonic', side_effect=[0, 0, 0, 301]):
            with self.assertRaises(TimeoutError):
                update_check.download_asset('https://example.invalid/a', Path(directory), digest=DIGEST)
            self.assertEqual(list(Path(directory).iterdir()), [])
        response.read.assert_not_called()
        response.read1.assert_called_once()

    def test_deeply_nested_github_json_is_a_recoverable_invalid_response(self):
        body = b'[' * 60000 + b'0' + b']' * 60000
        verified_backup = {'latest': '1.14.0', 'html_url': 'https://backup.invalid/',
                           'assets': [], 'source': 'backup'}
        with mock.patch.object(update_check, '_state', update_check.get_status()), \
                mock.patch.object(update_check, 'build_github_opener', _opener(_Response(body))), \
                mock.patch.object(update_check, 'fetch_backup_release', return_value=verified_backup) as backup:
            update_check.run_check('1.13.0', server_url='https://backup.invalid/latest.json')
            self.assertEqual(update_check.get_status()['source'], 'backup')
            self.assertIsNone(update_check.get_status()['error'])
        backup.assert_called_once_with('https://backup.invalid/latest.json')

    def test_invalid_url_or_size_is_rejected_without_file_or_request(self):
        for kwargs in ({'url': 'http://example.invalid/a'}, {'url': 'https://user:pw@example.invalid/a'},
                       {'size': 0}, {'size': True}, {'size': update_check.MAX_ASSET_BYTES + 1}):
            arguments = {'url': 'https://example.invalid/a', 'digest': DIGEST, **kwargs}
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as tmp, \
                    mock.patch.object(update_check, 'build_github_opener') as opener:
                with self.assertRaises(ValueError):
                    update_check.download_asset(dest_dir=Path(tmp), **arguments)
                opener.assert_not_called()
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_size_mismatch_overrun_deadline_and_redirect_all_remove_temporary_file(self):
        for size, limit, final_url, clock in (
            (len(PAYLOAD) + 1, None, None, None),
            (len(PAYLOAD) - 1, None, None, None),
            (None, len(PAYLOAD) - 1, None, None),
            (None, None, 'http://example.invalid/downgrade', None),
            (None, None, None, [0, 0, 301]),
        ):
            with self.subTest(size=size, limit=limit, final_url=final_url, clock=clock), \
                    tempfile.TemporaryDirectory() as tmp, __import__('contextlib').ExitStack() as stack:
                response = _Response(PAYLOAD)
                if final_url:
                    response.geturl = lambda: final_url
                stack.enter_context(mock.patch.object(update_check, 'build_github_opener', _opener(response)))
                if limit:
                    stack.enter_context(mock.patch.object(update_check, 'MAX_ASSET_BYTES', limit))
                if clock:
                    stack.enter_context(mock.patch.object(update_check.time, 'monotonic', side_effect=clock))
                with self.assertRaises((ValueError, OSError)):
                    update_check.download_asset('https://example.invalid/a', Path(tmp), digest=DIGEST, size=size)
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_redirect_handler_blocks_http_before_following_it(self):
        from urllib.request import Request
        handler = update_check._HTTPSOnlyRedirect()
        for url in ('http://insecure.invalid/a', 'file:///a', 'https://user:pw@example.invalid/a'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(Request('https://example.invalid/a'), None, 302, 'found', {}, url)

    def test_manifest_fetch_is_bounded_and_invokes_signature_verifier(self):
        with mock.patch.object(update_check, 'build_github_opener', _opener(_Response(b'signed'))), \
                mock.patch.object(update_check, 'verify_manifest', return_value={'latest': '1.14.0'}) as verify:
            self.assertEqual(update_check.fetch_backup_release('https://backup.invalid/latest.json'), {'latest': '1.14.0'})
        verify.assert_called_once_with(b'signed', update_check.TRUSTED_UPDATE_KEYS)
        with mock.patch.object(update_check, 'build_github_opener', _opener(_Response(b'x' * (update_check.MAX_MANIFEST_BYTES + 1)))):
            with self.assertRaises(ValueError):
                update_check.fetch_backup_release('https://backup.invalid/latest.json')


class RunCheckTest(unittest.TestCase):
    def setUp(self):
        self.patch = mock.patch.object(update_check, '_state', update_check.get_status())
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.channel = mock.patch.object(update_check, 'UPDATE_MANIFEST_URL', '')
        self.channel.start()
        self.addCleanup(self.channel.stop)

    def _check(self, data, current='1.11.1'):
        with mock.patch.object(update_check, 'fetch_latest_release', return_value=data):
            update_check.run_check(current)
        return update_check.get_status()

    def test_versions_are_compared_and_assets_published_together(self):
        release = {'tag_name': ' v2.0 ', 'assets': [{
            'name': 'app.exe', 'browser_download_url': 'https://example.invalid/app.exe', 'digest': DIGEST,
        }]}
        for current, has_update, ahead in (('1.11.1', True, False), ('2.0.0', False, False), ('2.1', False, True)):
            with self.subTest(current=current):
                state = self._check(release, current)
                self.assertTrue(state['checked'])
                self.assertIsNone(state['error'])
                self.assertEqual((state['has_update'], state['ahead_of_release']), (has_update, ahead))
                self.assertEqual(state['latest'], '2.0')
                self.assertEqual(state['html_url'], update_check.RELEASES_PAGE_URL)
                self.assertEqual(state['assets'][0]['digest'], DIGEST)

    def test_invalid_response_is_an_error_not_a_claim_that_the_app_is_current(self):
        for data in (None, [], {}, {'tag_name': None}, {'tag_name': ''}, {'tag_name': 'oops'},
                     {'tag_name': 'v2.0', 'assets': 'invalid'}):
            with self.subTest(data=data):
                state = self._check(data)
                self.assertTrue(state['error'])
                self.assertFalse(state['has_update'])
                self.assertIsNone(state['latest'])
                self.assertEqual(state['assets'], [])

    def test_release_tag_suffixes_keep_the_existing_version_comparison(self):
        state = self._check({'tag_name': 'v1.12.0-hotfix'})
        self.assertIsNone(state['error'])
        self.assertTrue(state['has_update'])
        self.assertEqual(state['latest'], '1.12.0-hotfix')

    def test_network_failure_clears_old_assets_and_does_not_prevent_retry(self):
        errors = (URLError('offline'), HTTPError('https://example.invalid', 403, 'rate limit', {}, None),
                  TimeoutError(), IncompleteRead(b'{', 5), ValueError('bad json'))
        for error in errors:
            with self.subTest(error=error):
                self._check({'tag_name': 'v2.0', 'assets': [{
                    'name': 'a.exe', 'browser_download_url': 'https://example.invalid/a.exe', 'digest': DIGEST,
                }]})
                with mock.patch.object(update_check, 'fetch_latest_release', side_effect=error):
                    update_check.run_check('1.11.1')
                state = update_check.get_status()
                self.assertTrue(state['error'])
                self.assertEqual(state['assets'], [])
                self.assertFalse(state['has_update'])
                self.assertIsNone(self._check({'tag_name': 'v2.1'})['error'])

    def test_readers_do_not_see_partially_updated_status(self):
        previous = self._check({'tag_name': 'v1.11.1'})
        started, finish = threading.Event(), threading.Event()

        def fetch():
            started.set()
            finish.wait(timeout=5)
            return {'tag_name': 'v2.0'}

        with mock.patch.object(update_check, 'fetch_latest_release', side_effect=fetch):
            worker = threading.Thread(target=update_check.run_check, args=('1.11.1',))
            worker.start()
            try:
                self.assertTrue(started.wait(timeout=5))
                self.assertEqual(update_check.get_status(), previous)
            finally:
                finish.set()
                worker.join(timeout=5)
        self.assertEqual(update_check.get_status()['latest'], '2.0')

    def test_missing_release_keeps_http_status_for_the_manual_check_ui(self):
        error = HTTPError(update_check.RELEASES_LATEST_API, 404, 'Not Found', {}, None)
        with mock.patch.object(update_check, 'fetch_latest_release', side_effect=error):
            update_check.run_check('1.12.1')
        state = update_check.get_status()
        self.assertEqual(state['http_status'], 404)
        self.assertFalse(state['has_update'])
        self.assertIsNone(state['latest'])
        self.assertIsNone(self._check({'tag_name': 'v1.12.1'})['http_status'])

    def test_asset_and_status_snapshots_cannot_modify_internal_state(self):
        self._check({'tag_name': 'v2.0', 'assets': [{
            'name': 'a.exe', 'browser_download_url': 'https://example.invalid/a.exe', 'digest': DIGEST,
        }]})
        asset = update_check.find_asset('a.exe')
        asset['digest'] = 'bad'
        snapshot = update_check.get_status()
        snapshot['assets'][0]['digest'] = 'bad'
        snapshot['assets'].clear()
        self.assertEqual(update_check.find_asset('a.exe')['digest'], DIGEST)

    def test_old_cache_is_ignored_and_no_new_cache_is_written(self):
        from utils import tray_common

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.update_check_cache.json'
            old = '{"last_attempt_at": "invalid", "assets": "invalid"}'
            path.write_text(old, encoding='utf-8')
            with mock.patch.object(tray_common, 'APP_DIR', Path(tmp)):
                self.assertTrue(self._check({'tag_name': 'v2.0'})['has_update'])
            self.assertEqual(path.read_text(encoding='utf-8'), old)
            self.assertEqual(list(Path(tmp).iterdir()), [path])

    def test_fetch_is_one_request_without_etag_and_with_timeout(self):
        opener = _opener(_Response(json.dumps({'tag_name': 'v2.0'}).encode()))
        with mock.patch.object(update_check, 'build_github_opener', opener):
            self.assertEqual(update_check.fetch_latest_release(timeout=7)['tag_name'], 'v2.0')
        args, kwargs = opener.return_value.open.call_args
        self.assertEqual(args[0].full_url, update_check.RELEASES_LATEST_API)
        self.assertFalse(args[0].has_header('If-none-match'))
        self.assertEqual(kwargs['timeout'], 7)


class RelaunchEnvTest(unittest.TestCase):
    def test_old_and_new_bootloader_variables_and_bundle_subdirectories_are_removed(self):
        bundle = str(Path(tempfile.gettempdir()) / '_MEItest')
        env = {
            '_PYI_APPLICATION_HOME_DIR': bundle, '_PYI_ARCHIVE_FILE': 'old.exe',
            '_MEIPASS': bundle, '_MEIPASS2': bundle,
            'PATH': os.pathsep.join((bundle, bundle + os.sep + 'lib', bundle + '-other')),
        }
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(sys, '_MEIPASS', bundle, create=True):
            result = update_check.relaunch_env()
        self.assertEqual(result, {'PATH': bundle + '-other', 'PYINSTALLER_RESET_ENVIRONMENT': '1'})


if __name__ == '__main__':
    unittest.main()
