from contextlib import suppress
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

from helper_enrollment import EnrollmentProof, IPOwnershipVerifier, public_ip
from helper_registry import RegistryService, RegistryStore
from helper_registry_agent import RegistryTransport, disable_helper, enroll_helper, generate_agent_key
from proxy import registry_protocol as p
from tests.test_helper_protocol import _make_certificate


class HelperEnrollmentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "private"
        self.directory.mkdir(mode=0o700)
        self.registry = ec.generate_private_key(ec.SECP256R1())
        self.agent = ec.generate_private_key(ec.SECP256R1())
        self.device = ec.generate_private_key(ec.SECP256R1())
        self.proof = EnrollmentProof("9.9.9.9", 8444, "ab" * 32, self.agent, clock=lambda: 1000)
        outer = self
        class SyntheticVerifiedCallback:
            # No connection to this public IP: only synthetic callback verification.
            def verify(self, ip):
                nonce = p.b64encode(b"n" * 32)
                return IPOwnershipVerifier.verify_response(outer.proof.envelope(nonce), ip, nonce, now=1000)
        self.store = RegistryStore(self.directory / "registry.sqlite3")
        self.service = RegistryService(self.store, self.registry, clock=lambda: 1000, ownership_verifier=SyntheticVerifiedCallback())
        service = self.service
        class LocalTransport:
            def request(self, path, value):
                return service.dispatch(path, p.json_bytes(value))
        self.transport = LocalTransport()

    def tearDown(self):
        self.temp.cleanup()

    def test_private_metadata_loopback_and_non_numeric_targets_rejected_before_callback(self):
        for value in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fe80::1", "224.0.0.1", "192.0.2.1", "example.invalid", "::ffff:127.0.0.1"):
            with self.subTest(ip=value), self.assertRaises(p.RegistryError):
                public_ip(value)

    def test_agent_automatic_enrollment_needs_verified_ip_proof_and_no_global_token(self):
        descriptor = enroll_helper(self.transport, self.agent, self.registry.public_key(), "9.9.9.9", "ab" * 32,
                                   self.directory / "registry-config.json", now=1000)
        helper = self.store.helper(ip="9.9.9.9")
        self.assertEqual(helper["helper_id"], descriptor["helper_id"])
        self.assertEqual(p.public_key_der(self.agent.public_key()), helper["agent_key"])
        self.assertNotIn("token", descriptor)
        repeated = enroll_helper(self.transport, self.agent, self.registry.public_key(), "9.9.9.9", "ab" * 32,
                                 self.directory / "registry-config.json", now=1000)
        self.assertEqual(descriptor["helper_id"], repeated["helper_id"])

    def test_identity_conflict_and_admin_disabled_helper_cannot_be_overwritten(self):
        old = self.store.provision_helper("9.9.9.9", 8444, "cd" * 32, self.device.public_key())
        with self.assertRaisesRegex(p.RegistryError, "conflict"):
            enroll_helper(self.transport, self.agent, self.registry.public_key(), "9.9.9.9", "ab" * 32,
                          self.directory / "registry-config.json", now=1000)
        self.assertEqual(old, self.store.helper(ip="9.9.9.9")["helper_id"])
        self.store.provision_helper("9.9.9.9", 8444, "ab" * 32, self.agent.public_key(), enabled=False)
        with self.assertRaisesRegex(p.RegistryError, "denied"):
            enroll_helper(self.transport, self.agent, self.registry.public_key(), "9.9.9.9", "ab" * 32,
                          self.directory / "registry-config.json", now=1000)

    def test_callback_proof_binds_nonce_ip_expiry_and_signature(self):
        nonce = p.b64encode(b"n" * 32)
        envelope = self.proof.envelope(nonce)
        IPOwnershipVerifier.verify_response(envelope, "9.9.9.9", nonce, now=1000)
        for ip, challenge, now in (("8.8.8.8", nonce, 1000), ("9.9.9.9", p.b64encode(b"x" * 32), 1000), ("9.9.9.9", nonce, 1060)):
            with self.assertRaises(p.RegistryError):
                IPOwnershipVerifier.verify_response(envelope, ip, challenge, now=now)
        altered = dict(envelope, signature=p.b64encode(b"bad-signature"))
        with self.assertRaises(p.RegistryError):
            IPOwnershipVerifier.verify_response(altered, "9.9.9.9", nonce, now=1000)

    def test_lost_enrollment_reply_keeps_identity_and_recovers_only_rollback_state(self):
        key_path = self.directory / "agent.key"
        key = generate_agent_key(key_path)
        self.proof = EnrollmentProof("9.9.9.9", 8444, "ab" * 32, key, clock=lambda: 1000)
        good = self.transport
        class LostReply:
            def request(self, path, value):
                result = good.request(path, value)
                if path == "/v1/enroll-helper":
                    raise p.RegistryError("unavailable")
                return result
        output = self.directory / "registry-config.json"
        with self.assertRaisesRegex(p.RegistryError, "unavailable"):
            enroll_helper(LostReply(), key, self.registry.public_key(), "9.9.9.9", "ab" * 32, output, now=1000)
        identifier = self.store.helper(ip="9.9.9.9")["helper_id"]
        retained = generate_agent_key(key_path)
        self.assertEqual(p.device_id(key.public_key()), p.device_id(retained.public_key()))
        disable_helper(good, retained, self.registry.public_key(), None, "ab" * 32, output, ip="9.9.9.9", now=1000)
        self.assertTrue(self.store.helper(identifier=identifier, include_disabled=True)["rollback_disabled"])
        # A fresh failed installation may no longer have the staged 8444 leaf.
        # Recovery needs the SAME agent key and a new verified CA/IP callback.
        self.proof = EnrollmentProof("9.9.9.9", 8444, "cd" * 32, retained, clock=lambda: 1000)
        result = enroll_helper(good, retained, self.registry.public_key(), "9.9.9.9", "cd" * 32, output, now=1000)
        self.assertEqual(identifier, result["helper_id"])
        self.assertEqual("cd" * 32, result["fingerprint"])
        self.assertFalse(self.store.helper(identifier=identifier)["rollback_disabled"])

    def test_local_write_failure_does_not_turn_rollback_into_admin_reenable(self):
        output = self.directory / "registry-config.json"
        with patch("helper_registry_agent.write_configuration", side_effect=OSError("synthetic write failure")), self.assertRaises(OSError):
            enroll_helper(self.transport, self.agent, self.registry.public_key(), "9.9.9.9", "ab" * 32, output, now=1000)
        helper = self.store.helper(ip="9.9.9.9")
        self.store.provision_helper("9.9.9.9", 8444, "ab" * 32, self.agent.public_key(), enabled=False)
        with self.assertRaisesRegex(p.RegistryError, "denied"):
            disable_helper(self.transport, self.agent, self.registry.public_key(), helper["helper_id"], "ab" * 32, output, now=1000)
        self.assertFalse(self.store.helper(ip="9.9.9.9", include_disabled=True)["rollback_disabled"])
        with self.assertRaisesRegex(p.RegistryError, "denied"):
            enroll_helper(self.transport, self.agent, self.registry.public_key(), "9.9.9.9", "ab" * 32, output, now=1000)


class AgentHTTPSDeadlineTest(unittest.TestCase):
    def run_trickle(self, *, cancelled=False, trusted=True, header_trickle=False):
        with tempfile.TemporaryDirectory() as directory:
            cert, key, _ = _make_certificate(Path(directory))
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert, key)
            trust = ssl.create_default_context(cafile=str(cert))
            trust.check_hostname = False  # Synthetic test CA only; production exposes no such switch.
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(2)
            port = listener.getsockname()[1]
            finished = threading.Event()
            def serve():
                try:
                    raw, _ = listener.accept()
                    raw.settimeout(2)
                    with server_context.wrap_socket(raw, server_side=True) as secured:
                        request = bytearray()
                        while b"\r\n\r\n" not in request:
                            chunk = secured.recv(1024)
                            if not chunk:
                                raise OSError()
                            request.extend(chunk)
                        headers, body = bytes(request).split(b"\r\n\r\n", 1)
                        length = next(int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n") if line.lower().startswith(b"content-length:"))
                        while len(body) < length:
                            chunk = secured.recv(length - len(body))
                            if not chunk:
                                raise OSError()
                            body += chunk
                        header = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\nConnection: close\r\n\r\n"
                        if not header_trickle:
                            secured.sendall(header)
                        for byte in (header if header_trickle else b" " * 500):
                            secured.sendall(bytes((byte,)))
                            if finished.wait(0.01):
                                break
                except OSError:
                    pass
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            cancel = threading.Event()
            transport = RegistryTransport("https://127.0.0.1:" + str(port), cancelled=cancel)
            cancellation = threading.Timer(0.12, cancel.set) if cancelled else None
            if cancellation:
                cancellation.start()
            started = time.monotonic()
            try:
                with patch("helper_registry_agent.REQUEST_TIMEOUT", 0.3), patch(
                        "helper_registry_agent.ssl.create_default_context", return_value=trust) if trusted else suppress():
                    with self.assertRaisesRegex(p.RegistryError, "cancelled" if cancelled else "unavailable"):
                        transport.request("/v1/challenge", dict(v=1))
                self.assertLess(time.monotonic() - started, 1.5)
            finally:
                finished.set()
                if cancellation:
                    cancellation.cancel()
                listener.close()
                worker.join(timeout=2)

    def test_slow_header_and_slow_body_have_absolute_deadline(self):
        self.run_trickle(header_trickle=True)
        self.run_trickle(header_trickle=False)

    def test_inflight_cancel_interrupts_response(self):
        self.run_trickle(cancelled=True)

    def test_self_signed_https_is_not_accepted(self):
        self.run_trickle(trusted=False)
