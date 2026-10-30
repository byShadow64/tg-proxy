"""Local CA/registry interoperability; no production requests or credentials."""
import copy
import datetime
import ipaddress
import json
from pathlib import Path
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
        self.server = RegistryHTTPServer(("127.0.0.1", 0), self.service)
        self.server.socket = server_context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "https://127.0.0.1:" + str(self.server.server_port)
        self.client = RegistryClient(self.identity, base_url=self.url,
            public_key=p.encode_public_key(self.signer.public_key()), ssl_context=self.context)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

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
