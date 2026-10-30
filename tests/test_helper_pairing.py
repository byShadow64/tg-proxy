"""Synthetic owner codes only; real TLS tests bind exclusively to loopback."""
import asyncio
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from helper_pairing import (
    DENIED, MAGIC, MAX_ACTIVE, MAX_ATTEMPTS, MAX_REQUEST,
    MAX_RESPONSE, PairingStore, b64decode, b64encode, certificate_digest, client_proof,
    json_bytes, parse_code, parse_json, server_proof,
)
from helper_server import HelperServer, read_frame, write_frame
from tests.test_helper_protocol import _make_certificate
from utils.helper_pairing import (PairingCancelled, PairingError, pair_helper,
                                  parse_endpoint, verify_response)

TOKEN = "synthetic-pairing-token-" + "x" * 40
CERTIFICATE = hashlib.sha256(b"synthetic-leaf-cert").digest()


def request(code, certificate=CERTIFICATE, nonce=b"n" * 32, *, proof=None):
    identifier, key = parse_code(code)
    return json_bytes(dict(v=1, id=identifier, nonce=b64encode(nonce), proof=b64encode(
        client_proof(key, identifier, nonce, certificate) if proof is None else proof)))


class CertificateDigestTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cert, _, self.fingerprint = _make_certificate(self.root)

    def test_first_leaf_is_exact_with_additional_certificates_and_leading_comments(self):
        pem = self.cert.read_text(encoding="ascii")
        self.assertEqual(certificate_digest("# Managed certificate chain\n" + pem + pem).hex(), self.fingerprint)
        self.assertEqual(certificate_digest(pem).hex(), self.fingerprint)

    def test_missing_truncated_base64_and_malformed_der_are_rejected(self):
        for pem in ("", "not a certificate", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
                    "-----BEGIN CERTIFICATE-----\n!not-base64!\n-----END CERTIFICATE-----",
                    self.cert.read_text(encoding="ascii").replace("-----END CERTIFICATE-----", "")):
            with self.subTest(length=len(pem)), self.assertRaises(ValueError):
                certificate_digest(pem)

    def test_installer_result_uses_leaf_digest_and_preserves_the_chain(self):
        script = (Path(__file__).resolve().parents[1] / "deploy_helper.sh").read_text(encoding="utf-8")
        programs = re.findall(r"<<'PY'\n(.*?)\nPY", script, re.DOTALL)
        chain = self.cert.read_text(encoding="ascii") * 2
        self.cert.write_text(chain, encoding="ascii")
        (self.root / "token").write_text(TOKEN)
        result = self.root / "result.json"
        # The installer preflight must execute, including key/chain loading.
        with patch("sys.argv", ["candidate-credentials", str(self.root)]):
            exec(compile(programs[0], "installer-candidate", "exec"), {"__name__": "__main__"})
        with patch("sys.argv", ["write-result", str(self.root), str(result), "8444", str(self.root)]), \
                patch("subprocess.check_output", return_value="203.0.113.10 "), \
                patch("os.fchmod", create=True):
            exec(compile(programs[2], "installer-result", "exec"), {"__name__": "__main__"})
        value = json.loads(result.read_text())
        self.assertEqual(value["fingerprint"], self.fingerprint)
        self.assertEqual(value["token"], TOKEN)
        self.assertEqual(self.cert.read_text(encoding="ascii"), chain)


class PairingStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state" / "pairing.sqlite3"
        self.store = PairingStore(self.path)

    def test_state_contains_derived_key_only_and_owner_private_files(self):
        code = self.store.issue()
        identifier, key = parse_code(code)
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute("SELECT id,key FROM codes").fetchone()
        self.assertEqual(row, (identifier, key))
        self.assertNotIn(code.encode(), self.path.read_bytes())
        self.assertNotIn(code.split(".")[2].encode(), self.path.read_bytes())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_cross_language_public_interoperability_vector(self):
        value = json.loads((Path(__file__).parent / "fixtures" / "helper_pairing_v1.json").read_text())
        identifier, key = parse_code(value["code"])
        nonce, server_nonce = b64decode(value["client_nonce"], 32), b64decode(value["server_nonce"], 32)
        certificate = bytes.fromhex(value["certificate_sha256_hex"])
        self.assertEqual(identifier, value["id"])
        self.assertEqual(key.hex(), value["key_hex"])
        self.assertEqual(client_proof(key, identifier, nonce, certificate).hex(), value["client_proof_hex"])
        self.assertEqual(server_proof(key, identifier, nonce, server_nonce, certificate,
                         b64decode(value["payload_base64url"])).hex(), value["server_proof_hex"])
        self.assertEqual(request(value["code"], certificate, nonce).decode(), value["request_utf8"])
        self.assertEqual(b64decode(value["payload_base64url"]).decode(), value["payload_utf8"])
        response = json.loads(value["response_utf8"])
        self.assertEqual(b64decode(response["proof"]).hex(), value["server_proof_hex"])

    def test_pairing_rejects_existing_tokens_with_control_characters_or_whitespace(self):
        code = self.store.issue()
        for token in ("\x01" * 512, " " + TOKEN, TOKEN + " ", TOKEN + "\x7f", TOKEN + "\ninside"):
            with self.subTest(token_length=len(token)), self.assertRaises(ValueError):
                self.store.redeem(request(code), CERTIFICATE, token, 8444)
        response = self.store.redeem(request(code), CERTIFICATE, "я" * 256, 8444)
        self.assertLessEqual(len(response), MAX_RESPONSE)
        self.assertNotEqual(response, DENIED)

    @unittest.skipIf(os.name == "nt", "POSIX permission checks apply on service hosts")
    def test_unsafe_existing_directory_and_database_permissions_rejected(self):
        self.path.parent.chmod(0o755)
        with self.assertRaises(ValueError):
            PairingStore(self.path)
        self.path.parent.chmod(0o700)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            PairingStore(self.path)

    def test_symlinked_state_or_database_rejected(self):
        target = self.path.parent.parent / "link"
        try:
            target.symlink_to(self.path.parent, target_is_directory=True)
        except OSError:
            self.skipTest("Symlinks unavailable")
        with self.assertRaises(ValueError):
            PairingStore(target / "pairing.sqlite3")
        alias = self.path.parent / "alias.sqlite3"
        alias.symlink_to(self.path)
        with self.assertRaises((ValueError, OSError)):
            PairingStore(alias)

    def test_limits_ttl_and_cleanup_bound_active_state(self):
        for ttl in (0, 601, -1, True, 1.5):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                self.store.issue(ttl=ttl)
        for _ in range(MAX_ACTIVE):
            self.store.issue(now=100, ttl=300)
        with self.assertRaises(ValueError):
            self.store.issue(now=100)
        code = self.store.issue(now=401)
        self.assertNotEqual(self.store.redeem(request(code), CERTIFICATE, TOKEN, 8444, now=402), DENIED)

    def test_unknown_expired_used_and_wrong_codes_have_identical_denial(self):
        unknown = PairingStore(self.path.parent / "other.sqlite3").issue(now=100)
        expired = self.store.issue(ttl=1, now=100)
        correct = self.store.issue(now=100)
        self.assertEqual(self.store.redeem(request(unknown), CERTIFICATE, TOKEN, 8444, now=100), DENIED)
        self.assertEqual(self.store.redeem(request(expired), CERTIFICATE, TOKEN, 8444, now=101), DENIED)
        self.assertEqual(self.store.redeem(request(correct, proof=b"\0" * 32), CERTIFICATE, TOKEN, 8444, now=100), DENIED)
        self.assertNotEqual(self.store.redeem(request(correct), CERTIFICATE, TOKEN, 8444, now=100), DENIED)
        self.assertEqual(self.store.redeem(request(correct), CERTIFICATE, TOKEN, 8444, now=100), DENIED)

    def test_attempt_limit_is_atomic_and_rejected_proofs_never_return_token(self):
        code = self.store.issue()
        for _ in range(MAX_ATTEMPTS):
            response = self.store.redeem(request(code, proof=b"\0" * 32), CERTIFICATE, TOKEN, 8444)
            self.assertEqual(response, DENIED)
            self.assertNotIn(TOKEN.encode(), response)
        self.assertEqual(self.store.redeem(request(code), CERTIFICATE, TOKEN, 8444), DENIED)

    def test_concurrent_redeem_has_exactly_one_winner_and_survives_restart(self):
        code = self.store.issue()
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: self.store.redeem(request(code), CERTIFICATE, TOKEN, 8444), range(8)))
        self.assertEqual(sum(result != DENIED for result in results), 1)
        self.assertEqual(PairingStore(self.path).redeem(request(code), CERTIFICATE, TOKEN, 8444), DENIED)

    def test_certificate_substitution_fails_and_does_not_consume_on_first_failure(self):
        code = self.store.issue()
        self.assertEqual(self.store.redeem(request(code, b"z" * 32), CERTIFICATE, TOKEN, 8444), DENIED)
        self.assertNotEqual(self.store.redeem(request(code), CERTIFICATE, TOKEN, 8444), DENIED)

    def test_malformed_requests_denied_with_size_duplicates_and_canonical_base64(self):
        code = self.store.issue()
        correct = request(code)
        candidates = [b"", b"{" + b"x" * MAX_REQUEST, b"[]", b'{"v":1,"v":1}',
                      b'{"v":true}', b'{"v":1,"nonce":NaN}', b"\xff"]
        value = json.loads(correct)
        for name in ("nonce", "proof", "id"):
            changed = dict(value)
            changed[name] += "="
            candidates.append(json_bytes(changed))
        for candidate in candidates:
            with self.subTest(candidate_length=len(candidate)):
                self.assertEqual(self.store.redeem(candidate, CERTIFICATE, TOKEN, 8444), DENIED)

    def test_response_authenticates_raw_payload_before_json_and_preserves_reachable_port(self):
        code = self.store.issue()
        identifier, key = parse_code(code)
        response = self.store.redeem(request(code), CERTIFICATE, TOKEN, 8444)
        result = verify_response(response, identifier=identifier, key=key, nonce=b"n" * 32,
                                 certificate=CERTIFICATE, host="127.0.0.1", port=18444)
        self.assertEqual((result.host, result.port, result.tls_fingerprint, result.token),
                         ("127.0.0.1", 18444, CERTIFICATE.hex(), TOKEN))
        self.assertNotIn(TOKEN, repr(result))
        value = json.loads(response)
        value["payload"] = b64encode(b'{"v":1,"token":"attacker"}')
        with patch("utils.helper_pairing.parse_json", wraps=parse_json) as parse:
            with self.assertRaises(ValueError):
                verify_response(json_bytes(value), identifier=identifier, key=key, nonce=b"n" * 32,
                                certificate=CERTIFICATE, host="127.0.0.1", port=8444)
            self.assertEqual(parse.call_count, 1)  # Payload never parsed after failed HMAC.

    def test_signed_payload_requires_matching_pin_and_valid_token(self):
        code = self.store.issue()
        identifier, key = parse_code(code)
        for token, pin, port in (("short", CERTIFICATE.hex(), 8444), (TOKEN, "0" * 64, 8444),
                                 (TOKEN, CERTIFICATE.hex(), True), (TOKEN, CERTIFICATE.hex(), 0),
                                 (TOKEN + "\x01", CERTIFICATE.hex(), 8444), (TOKEN + "\x7f", CERTIFICATE.hex(), 8444)):
            payload = json_bytes(dict(v=1, token=token, fingerprint=pin, port=port))
            value = dict(v=1, nonce=b64encode(b"s" * 32), payload=b64encode(payload), proof=b64encode(
                server_proof(key, identifier, b"n" * 32, b"s" * 32, CERTIFICATE, payload)))
            with self.assertRaises(ValueError):
                verify_response(json_bytes(value), identifier=identifier, key=key, nonce=b"n" * 32,
                                certificate=CERTIFICATE, host="127.0.0.1", port=8444)

    def test_owner_code_and_endpoint_parsers_reject_ambiguous_inputs(self):
        code = self.store.issue()
        for bad in (code + "=", code + "\n", "tg1" + code[3:], "TG1.a.b", 1):
            with self.subTest(bad_type=type(bad).__name__), self.assertRaises(ValueError):
                parse_code(bad)
        self.assertEqual(parse_endpoint("127.0.0.1:18444"), ("127.0.0.1", 18444))
        self.assertEqual(parse_endpoint("[::1]:18444"), ("::1", 18444))
        self.assertEqual(parse_endpoint("::1"), ("::1", 8444))
        for bad in ("https://127.0.0.1", "attacker.example", "127.0.0.1:0", "127.0.0.1:65536", "::1%1", "[]"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_endpoint(bad)


class PairingTLSTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.cert, self.key, self.fingerprint = _make_certificate(root)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(self.cert, self.key)
        self.store = PairingStore(root / "state" / "pairing.sqlite3")
        self.helper = HelperServer(TOKEN, pairing_store=self.store, certificate_digest=bytes.fromhex(self.fingerprint))
        self.server = await asyncio.start_server(lambda r, w: self.helper.handle(r, w, secure=True),
                                                 "127.0.0.1", 0, ssl=self.context)
        self.port = self.server.sockets[0].getsockname()[1]
        self.extra_servers = []

    async def asyncTearDown(self):
        for server in (self.server, *self.extra_servers):
            server.close()
            await server.wait_closed()
        await self.helper.close_clients()
        self.temp.cleanup()

    async def pair(self, code, **kwargs):
        return await asyncio.to_thread(pair_helper, "127.0.0.1", code, self.port, **kwargs)

    async def test_real_tls_success_replay_and_normal_helper_compatibility(self):
        code = self.store.issue()
        result = await self.pair(code)
        self.assertEqual((result.token, result.tls_fingerprint, result.port), (TOKEN, self.fingerprint, self.port))
        with self.assertRaises(PairingError):
            await self.pair(code)
        reached = []

        async def relay(reader, writer, domain, *, secure):
            reached.append(domain)
            await write_frame(writer, b"OK", 1)

        self.helper._relay = relay
        from proxy.helper_conn import HelperConnection
        connection = await HelperConnection.connect_v2("127.0.0.1", self.port, self.fingerprint, TOKEN,
                                                       "kws2.web.telegram.org")
        await connection.close()
        self.assertEqual(reached, ["kws2.web.telegram.org"])

    async def test_real_tls_certificate_chain_pairing_matches_the_actual_leaf(self):
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        original = x509.load_pem_x509_certificate(self.cert.read_bytes())
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "synthetic-helper-ca")])
        now = datetime.datetime.now(datetime.timezone.utc)
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
              .sign(ca_key, hashes.SHA256()))
        leaf = (x509.CertificateBuilder().subject_name(original.subject).issuer_name(ca.subject)
                .public_key(original.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
                .sign(ca_key, hashes.SHA256()))
        chain = (b"# Managed TLS chain\n" + leaf.public_bytes(serialization.Encoding.PEM)
                 + ca.public_bytes(serialization.Encoding.PEM))
        self.cert.write_bytes(chain)
        self.context.load_cert_chain(self.cert, self.key)
        self.helper._certificate_digest = certificate_digest(chain.decode("ascii"))
        result = await self.pair(self.store.issue())
        self.assertEqual(result.tls_fingerprint, leaf.fingerprint(hashes.SHA256()).hex())
        self.assertEqual(result.token, TOKEN)
        self.assertEqual(self.cert.read_bytes(), chain)
        # Execute the actual installer verification program against this TLS
        # listener, including its live getpeercert/hash branch and chain file.
        script = (Path(__file__).resolve().parents[1] / "deploy_helper.sh").read_text(encoding="utf-8")
        program = re.findall(r"<<'PY'\n(.*?)\nPY", script, re.DOTALL)[1]

        def verify_installed_listener():
            with patch("sys.argv", ["verify-listener", str(self.cert), str(self.port), str(self.cert.parent)]), \
                    patch("subprocess.run", return_value=SimpleNamespace(returncode=0)):
                exec(compile(program, "installer-listener", "exec"), {"__name__": "__main__"})

        await asyncio.wait_for(asyncio.to_thread(verify_installed_listener), 2)

    async def test_wire_contains_only_challenge_not_owner_code_or_token(self):
        captured = []

        async def spy(reader, writer):
            try:
                captured.extend((await read_frame(reader, 1, max_size=512),
                                 await read_frame(reader, 1, max_size=MAX_REQUEST)))
                await write_frame(writer, DENIED, 1)
            finally:
                writer.close()

        server = await asyncio.start_server(spy, "127.0.0.1", 0, ssl=self.context)
        self.extra_servers.append(server)
        code = self.store.issue()
        with self.assertRaises(PairingError):
            await asyncio.to_thread(pair_helper, "127.0.0.1", code, server.sockets[0].getsockname()[1])
        self.assertEqual(captured[0], MAGIC)
        wire = b"".join(captured)
        self.assertNotIn(code.encode(), wire)
        self.assertNotIn(code.split(".")[2].encode(), wire)
        self.assertNotIn(TOKEN.encode(), wire)
        self.assertEqual(set(json.loads(captured[1])), {"v", "id", "nonce", "proof"})

    async def test_real_tls_mitm_with_substituted_cert_cannot_relay_pairing_proof(self):
        other = Path(self.temp.name) / "other"
        other.mkdir()
        cert, key, _ = _make_certificate(other)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        outcomes = []

        async def mitm(reader, writer):
            try:
                self.assertEqual(await read_frame(reader, 1), MAGIC)
                supplied = await read_frame(reader, 1)
                response = self.store.redeem(supplied, bytes.fromhex(self.fingerprint), TOKEN, self.port)
                outcomes.append(response)
                await write_frame(writer, response, 1)
            finally:
                writer.close()

        server = await asyncio.start_server(mitm, "127.0.0.1", 0, ssl=context)
        self.extra_servers.append(server)
        code = self.store.issue()
        with self.assertRaises(PairingError):
            await asyncio.to_thread(pair_helper, "127.0.0.1", code, server.sockets[0].getsockname()[1])
        self.assertEqual(outcomes, [DENIED])
        result = await self.pair(code)
        self.assertEqual(result.token, TOKEN)

    async def test_tls_cancellation_and_overall_deadline_close_hanging_connection(self):
        disconnected = asyncio.Event()

        async def hang(reader, writer):
            try:
                await read_frame(reader, 1)
                await read_frame(reader, 1)
                await reader.read()
                disconnected.set()
            finally:
                writer.close()

        server = await asyncio.start_server(hang, "127.0.0.1", 0, ssl=self.context)
        self.extra_servers.append(server)
        port = server.sockets[0].getsockname()[1]
        for cancelled in (False, True):
            disconnected.clear()
            cancel = threading.Event()
            task = asyncio.create_task(asyncio.to_thread(pair_helper, "127.0.0.1", self.store.issue(), port,
                                                        timeout=0.2 if not cancelled else 3, cancel_event=cancel))
            if cancelled:
                await asyncio.sleep(0.1)
                cancel.set()
            with self.assertRaises(PairingCancelled if cancelled else PairingError):
                await asyncio.wait_for(task, 1)
            await asyncio.wait_for(disconnected.wait(), 1)

    async def test_pairing_disabled_is_uniformly_denied_and_no_relay(self):
        self.helper._pairing_store = None
        with self.assertRaises(PairingError):
            await self.pair(self.store.issue())

    async def test_server_pairing_rate_limits_are_bounded_per_ip_and_globally(self):
        helper = HelperServer(TOKEN)
        self.assertTrue(all(helper._admit_pairing("one") for _ in range(10)))
        self.assertFalse(helper._admit_pairing("one"))
        self.assertTrue(all(helper._admit_pairing(str(i)) for i in range(110)))
        self.assertFalse(helper._admit_pairing("new"))
        with patch("helper_server.time.monotonic", return_value=time.monotonic() + 61):
            self.assertTrue(helper._admit_pairing("one"))
        self.assertEqual(len(helper._pairing_attempts), 1)
        self.assertEqual(len(helper._pairing_per_ip), 1)


if __name__ == "__main__":
    unittest.main()
