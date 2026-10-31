"""Local CA/registry interoperability; no production requests or credentials."""
import copy
import datetime
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from helper_registry import RegistryHTTPServer, RegistryService, RegistryStore
from proxy import registry_protocol as p
from utils.device_identity import DeviceIdentity
from utils.helper_registry import RegistryClient, RegistryError, RegistryCancelled


class _TLSRegistryHTTPServer(RegistryHTTPServer):
    """Test TLS terminator with the production connection limit and owned I/O."""

    def __init__(self, address, service, context):
        self._tls_context = context
        self._owned = threading.Condition()
        self._workers = set()
        self._all_workers = []
        self._requests = {}
        self._phases = {}
        self._stopping = False
        self._stopped = False
        self._shutdown_thread = None
        self.handshake_entered = threading.Event()
        self.http_entered = threading.Event()
        self.unexpected_errors = []
        super().__init__(address, service)

    def process_request(self, request, client_address):
        # Keep the real RegistryHTTPServer's exact bounded semaphore policy.
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        worker = threading.Thread(target=self.process_request_thread,
            args=(request, client_address), name="registry-test-request", daemon=True)
        with self._owned:
            if self._stopping:
                self.slots.release()
                self.shutdown_request(request)
                return
            self._workers.add(worker)
            self._all_workers.append(worker)
            self._requests[worker] = request
            self._phases[worker] = "accepted"
            try:
                worker.start()
            except BaseException:
                self._requests.pop(worker)
                self._phases.pop(worker)
                self._workers.remove(worker)
                self._all_workers.remove(worker)
                self.slots.release()
                self.shutdown_request(request)
                raise
            self._owned.notify_all()

    def process_request_thread(self, request, client_address):
        worker = threading.current_thread()
        secure, delegated = None, False
        try:
            # The listening socket stays plain. A stalled ClientHello occupies
            # one bounded worker, never the serve_forever accept/shutdown loop.
            with self._owned:
                if self._stopping:
                    return
                request.settimeout(5)
                secure = self._tls_context.wrap_socket(
                    request, server_side=True, do_handshake_on_connect=False)
                self._requests[worker] = secure
                self._phases[worker] = "tls_handshake"
            self.handshake_entered.set()
            secure.do_handshake()
            with self._owned:
                self._phases[worker] = "http_handler"
            self.http_entered.set()
            delegated = True
            # The production handler still sets its own HTTP deadline and
            # releases the already acquired connection slot exactly once.
            super().process_request_thread(secure, client_address)
        except (OSError, ssl.SSLError):
            pass  # Expected for rejected TLS, timeout and explicit shutdown.
        except BaseException as error:
            with self._owned:
                self.unexpected_errors.append(type(error).__name__)
        finally:
            if not delegated:
                self.slots.release()
            self.shutdown_request(secure if secure is not None else request)
            with self._owned:
                self._requests.pop(worker, None)
                self._phases.pop(worker, None)
                self._workers.remove(worker)
                self._owned.notify_all()

    def wait_for_workers(self, count, timeout=2):
        with self._owned:
            return self._owned.wait_for(lambda: len(self._workers) == count, timeout)

    def stop_owned(self, serving_thread, timeout=5):
        if self._stopped:
            return
        deadline = time.monotonic() + timeout
        with self._owned:
            self._stopping = True
            requests = list(self._requests.values())
        for request in requests:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            request.close()
        if self._shutdown_thread is None:
            self._shutdown_thread = threading.Thread(
                target=self.shutdown, name="registry-test-shutdown", daemon=True)
            self._shutdown_thread.start()
        self._shutdown_thread.join(max(0, deadline - time.monotonic()))
        self.server_close()
        serving_thread.join(max(0, deadline - time.monotonic()))
        with self._owned:
            workers = list(self._all_workers)
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))
        with self._owned:
            if (self._shutdown_thread.is_alive() or serving_thread.is_alive()
                    or any(worker.is_alive() for worker in self._all_workers)
                    or self._workers or self._requests):
                phases = list(self._phases.values())
                counts = tuple(phases.count(phase) for phase in
                    ("accepted", "tls_handshake", "http_handler"))
                raise AssertionError("Registry fixture still owns active I/O "
                    "(accepted=%d, tls_handshake=%d, http_handler=%d)" % counts)
            if self.unexpected_errors:
                raise AssertionError("Registry test worker failed unexpectedly")
        self._stopped = True


class IdentityTest(unittest.TestCase):
    def test_persisted_identity_signs_without_exposing_private_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            first, second = DeviceIdentity.load(path), DeviceIdentity.load(path)
            self.assertEqual(first.device_id, second.device_id)
            public = p.decode_public_key(first.public_key)
            public.verify(p.b64decode(second.sign(b"test challenge")), b"test challenge", ec.ECDSA(hashes.SHA256()))
            self.assertNotIn("PRIVATE KEY", path.read_text())
            self.assertNotIn(first.public_key, path.read_text())

    def test_hardlinked_key_and_corrupt_file_are_rejected(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            DeviceIdentity.load(path)
            alias = Path(directory) / "other"
            os.link(path, alias)
            with self.assertRaises(ValueError):
                DeviceIdentity.load(path)
            alias.unlink()
            path.write_text('{"v":true,"storage":"dpapi","key":"secret"}')
            with self.assertRaises(ValueError):
                DeviceIdentity.load(path)


class RegistryClientTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.signer = ec.generate_private_key(ec.SECP256R1())
        self.identity = DeviceIdentity(ec.generate_private_key(ec.SECP256R1()))
        self.agent = ec.generate_private_key(ec.SECP256R1())
        self.store = RegistryStore(self.root / "private/registry.sqlite3")
        self.service = RegistryService(self.store, self.signer)
        self.helper_id = self.store.provision_helper("192.0.2.10", 8444, "ab" * 32, self.agent.public_key())
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "registry-test")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
        certpath, keypath = self.root / "test.crt", self.root / "test.key"
        certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certpath, keypath)
        self.context = ssl.create_default_context(cafile=str(certpath))
        self.server = _TLSRegistryHTTPServer(("127.0.0.1", 0), self.service, server_context)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=.02),
            name="registry-test-listener", daemon=True)
        self.thread.start()
        self.url = "https://127.0.0.1:" + str(self.server.server_port)
        self.client = RegistryClient(self.identity, base_url=self.url,
            public_key=p.encode_public_key(self.signer.public_key()), ssl_context=self.context)

    def tearDown(self):
        self.server.stop_owned(self.thread)
        self.temp.cleanup()

    def assert_stopped_and_database_released(self):
        self.server.stop_owned(self.thread)
        self.assertFalse(self.thread.is_alive())
        self.assertTrue(self.server.wait_for_workers(0, timeout=0))
        self.assertFalse(self.server._requests)
        acquired = 0
        try:
            for _ in range(16):
                self.assertTrue(self.server.slots.acquire(blocking=False))
                acquired += 1
            self.assertFalse(self.server.slots.acquire(blocking=False))
        finally:
            for _ in range(acquired):
                self.server.slots.release()
        # Windows refuses this rename while a handler retains an open SQLite
        # handle. Do it only after every owned worker has been joined.
        database = self.root / "private/registry.sqlite3"
        released = database.with_suffix(".released")
        database.rename(released)
        released.rename(database)

    def test_raw_peer_cannot_block_verified_client_or_fixture_shutdown(self):
        raw = socket.create_connection(self.server.server_address, timeout=2)
        self.addCleanup(raw.close)
        self.assertTrue(self.server.handshake_entered.wait(2))
        self.assertIsNone(self.server.socket.gettimeout())
        self.assertNotIsInstance(self.server.socket, ssl.SSLSocket)
        # Real CA validation, device registration and signed lease still run
        # while the first peer withholds ClientHello.
        self.assertEqual(self.client.lease("192.0.2.10").host, "192.0.2.10")
        raw.settimeout(.05)
        with self.assertRaises(TimeoutError):
            raw.recv(1)
        self.assert_stopped_and_database_released()
        raw.settimeout(.5)
        self.assertEqual(raw.recv(1), b"")

    def test_incomplete_https_request_is_closed_before_database_cleanup(self):
        self.client.lease("192.0.2.10")
        self.assertTrue(self.server.wait_for_workers(0))
        self.server.http_entered.clear()
        secure = self.context.wrap_socket(
            socket.create_connection(self.server.server_address, timeout=2),
            server_hostname="127.0.0.1")
        self.addCleanup(secure.close)
        secure.sendall(b"POST /v1/register HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                       b"Content-Type: application/json\r\nContent-Length: 32\r\n\r\n{")
        self.assertTrue(self.server.http_entered.wait(2))
        self.assertTrue(self.server.wait_for_workers(1))
        secure.settimeout(.05)
        with self.assertRaises(TimeoutError):
            secure.recv(1)
        self.assert_stopped_and_database_released()

    def test_stalled_handshakes_keep_the_production_sixteen_connection_limit(self):
        peers = []
        for _ in range(16):
            peer = socket.create_connection(self.server.server_address, timeout=2)
            peers.append(peer)
            self.addCleanup(peer.close)
        self.assertTrue(self.server.wait_for_workers(16))
        rejected = socket.create_connection(self.server.server_address, timeout=2)
        self.addCleanup(rejected.close)
        rejected.settimeout(1)
        self.assertEqual(rejected.recv(1), b"")
        self.assertTrue(self.server.wait_for_workers(16, timeout=0))
        self.assert_stopped_and_database_released()

    def test_real_https_register_lease_cache_and_refresh(self):
        with patch.object(self.service, "dispatch", wraps=self.service.dispatch) as calls:
            lease = self.client.lease("192.0.2.10")
            self.assertEqual((lease.host, lease.port, lease.fingerprint), ("192.0.2.10", 8444, "ab" * 32))
            claims = p.verify_lease(lease.token, self.signer.public_key(), helper_id=self.helper_id,
                fingerprint=lease.fingerprint, device=self.identity.device_id)
            self.assertEqual(claims.device_id, self.identity.device_id)
            self.assertNotIn(lease.token, repr(lease))
            self.assertEqual(calls.call_count, 4)
            self.assertIs(self.client.lease("192.0.2.10"), lease)
            self.assertEqual(calls.call_count, 4)
            self.client._cache.clear()
            self.client.lease("192.0.2.10")
            self.assertEqual(calls.call_count, 6)

    def test_unknown_helper_is_distinct_and_not_cached(self):
        with self.assertRaisesRegex(RegistryError, "helper_not_found"):
            self.client.lease("192.0.2.11")
        self.assertFalse(self.client._cache)

    def test_failed_registry_has_bounded_cooldown_but_explicit_retry_works(self):
        with patch.object(self.service, "dispatch", wraps=self.service.dispatch) as calls:
            for _ in range(10):
                with self.assertRaisesRegex(RegistryError, "helper_not_found"):
                    self.client.lease("192.0.2.11")
            self.assertEqual(calls.call_count, 4)
            first_deadline = self.client._failures["192.0.2.11"][1]
            with self.assertRaises(RegistryError):
                self.client.lease("192.0.2.11")
            self.assertEqual(self.client._failures["192.0.2.11"][1], first_deadline)
            self.store.provision_helper("192.0.2.11", 8444, "ab"*32, self.agent.public_key())
            self.assertEqual(self.client.lease("192.0.2.11", force=True).host, "192.0.2.11")
            self.assertNotIn("192.0.2.11", self.client._failures)

    def test_untrusted_certificate_and_wrong_identity_fail_closed(self):
        client = RegistryClient(self.identity, base_url=self.url,
            public_key=p.encode_public_key(self.signer.public_key()))
        with self.assertRaises(RegistryError):
            client.lease("192.0.2.10")
        self.assertFalse(client._cache)

    def test_reclaimed_device_reenrolls_once_with_same_key_but_revoked_never_does(self):
        original = self.client.lease("192.0.2.10")
        self.client._cache.clear()
        with self.store._connect() as database:
            database.execute("DELETE FROM devices WHERE id=?", (self.identity.device_id,))
        with patch.object(self.service, "dispatch", wraps=self.service.dispatch) as calls:
            restored = self.client.lease("192.0.2.10")
            self.assertEqual(restored.helper_id, original.helper_id)
            self.assertEqual(sum(call.args[0] == "/v1/register" for call in calls.call_args_list), 1)
        self.store.set_device(self.identity.device_id, False)
        with patch.object(self.service, "dispatch", wraps=self.service.dispatch) as calls:
            with self.assertRaisesRegex(RegistryError, "device_denied"):
                self.client.lease("192.0.2.10", force=True)
            self.assertFalse(any(call.args[0] == "/v1/register" for call in calls.call_args_list))

    def test_unverified_tls_context_and_wrong_signing_key_are_rejected(self):
        with self.assertRaises(RegistryError):
            RegistryClient(self.identity, base_url=self.url, public_key=p.encode_public_key(self.signer.public_key()),
                ssl_context=ssl._create_unverified_context())
        wrong = ec.generate_private_key(ec.SECP256R1())
        client = RegistryClient(self.identity, base_url=self.url,
            public_key=p.encode_public_key(wrong.public_key()), ssl_context=self.context)
        with self.assertRaisesRegex(RegistryError, "invalid_registry_data"):
            client.lease("192.0.2.10")
        self.assertFalse(client._cache)

    def test_cancel_closes_active_https_without_saving_a_lease(self):
        entered, release, cancelled = threading.Event(), threading.Event(), threading.Event()
        dispatch = self.service.dispatch
        def blocked(*args, **kwargs):
            entered.set()
            release.wait(3)
            return dispatch(*args, **kwargs)
        errors = []
        def call():
            try:
                self.client.lease("192.0.2.10", cancelled=cancelled.is_set)
            except RegistryCancelled:
                errors.append("cancelled")
        with patch.object(self.service, "dispatch", side_effect=blocked):
            worker = threading.Thread(target=call)
            worker.start()
            self.assertTrue(entered.wait(2))
            cancelled.set()
            worker.join(1.5)
            release.set()
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors, ["cancelled"])
        self.assertFalse(self.client._cache)

    def test_signed_payload_cannot_change_ip_device_pin_or_expiry(self):
        now = int(time.time())
        descriptor = dict(v=1, helper_id=self.helper_id, ip="192.0.2.10", port=8444,
            fingerprint="ab" * 32, iat=now, exp=now+600,
            protocol=p.PROTOCOL, access=p.ACCESS)
        token = p.issue_lease(self.signer, self.helper_id, self.identity.device_id, "ab" * 32, now=now)
        for change in ({"ip":"192.0.2.11"}, {"fingerprint":"bc"*32}, {"exp":now-1}, {"exp":now+601}, {"port":True}, {"v":True}):
            with self.subTest(change=change):
                value = {**descriptor, **change}
                response = dict(v=1, descriptor=p.sign_envelope(value,self.signer),token=token)
                with self.assertRaises(RegistryError):
                    self.client._verify_lease(response, "192.0.2.10")
        other = DeviceIdentity(ec.generate_private_key(ec.SECP256R1()))
        token = p.issue_lease(self.signer, self.helper_id, other.device_id, "ab"*32, now=now)
        with self.assertRaises(RegistryError):
            self.client._verify_lease(dict(v=1,descriptor=p.sign_envelope(descriptor,self.signer),token=token),"192.0.2.10")
