from concurrent.futures import ThreadPoolExecutor
import http.client
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

from helper_registry import RateLimiter, RegistryHTTPServer, RegistryService, RegistryStore
from proxy import registry_protocol as p


class RegistryServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = RegistryStore(Path(self.temp.name) / "private/registry.sqlite3")
        self.registry = ec.generate_private_key(ec.SECP256R1())
        self.device = ec.generate_private_key(ec.SECP256R1())
        self.agent = ec.generate_private_key(ec.SECP256R1())
        self.now = 1000
        self.service = RegistryService(self.store, self.registry, clock=lambda: self.now)
        self.helper = self.store.provision_helper("192.0.2.10", 8444, "ab" * 32, self.agent.public_key())

    def tearDown(self):
        self.temp.cleanup()

    def call(self, path, value):
        return self.service.dispatch(path, p.json_bytes(value))

    def proof(self, key, purpose, target):
        challenge = self.call("/v1/challenge", dict(v=1, public_key=p.encode_public_key(key.public_key()), purpose=purpose, target=target))
        return p.make_device_proof(key, purpose, target, challenge["challenge"])

    def register(self):
        return self.call("/v1/register", self.proof(self.device, "register", ""))

    def test_public_registration_then_verified_helper_lease(self):
        result = self.register()
        self.assertEqual(p.ACCESS, result["access"])
        leased = self.call("/v1/lease", self.proof(self.device, "lease", "192.0.2.10"))
        self.assertEqual({"v", "token", "descriptor"}, set(leased))
        descriptor = p.verify_descriptor(leased["descriptor"], self.registry.public_key(), "192.0.2.10", now=1000)
        p.verify_lease(leased["token"], self.registry.public_key(), helper_id=self.helper,
                       fingerprint=descriptor["fingerprint"], device=result["device_id"], now=1000)
        self.assertNotIn("agent_key", p.b64decode(leased["descriptor"]["payload"]).decode())

    def test_unregistered_device_cannot_request_lease(self):
        with self.assertRaisesRegex(p.RegistryError, "device_not_registered"):
            self.proof(self.device, "lease", "192.0.2.10")

    def test_nonce_is_one_use_even_for_concurrent_redemption(self):
        proof = self.proof(self.device, "register", "")
        def redeem():
            try:
                self.call("/v1/register", proof)
                return True
            except p.RegistryError:
                return False
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: redeem(), range(2)))
        self.assertEqual(1, sum(results))

    def test_expired_wrong_target_and_bad_signature_are_rejected(self):
        proof = self.proof(self.device, "register", "")
        self.now += 61
        with self.assertRaises(p.RegistryError):
            self.call("/v1/register", proof)
        proof = self.proof(self.device, "register", "")
        proof["signature"] = p.b64encode(b"bad-signature")
        with self.assertRaises(p.RegistryError):
            self.call("/v1/register", proof)
        self.register()
        proof = self.proof(self.device, "lease", "192.0.2.10")
        proof["target"] = "192.0.2.11"
        with self.assertRaises(p.RegistryError):
            self.call("/v1/lease", proof)

    def test_invalid_signature_cannot_burn_another_pending_valid_proof(self):
        proof = self.proof(self.device, "register", "")
        wrong = dict(proof, signature=p.b64encode(b"invalid-signature"))
        with self.assertRaises(p.RegistryError):
            self.call("/v1/register", wrong)
        result = self.call("/v1/register", proof)
        self.assertEqual(p.device_id(self.device.public_key()), result["device_id"])

    def test_claiming_public_agent_key_cannot_fill_an_agent_specific_quota(self):
        for _ in range(4):
            self.proof(self.agent, "helper", self.helper)
        valid = self.proof(self.agent, "helper", self.helper)
        envelope = self.call("/v1/helper-config", valid)
        self.assertTrue(p.verify_helper_config(envelope, self.registry.public_key(), now=1000)["enabled"])

    def test_device_cannot_claim_foreign_helper_or_obtain_agent_configuration(self):
        self.register()
        with self.assertRaisesRegex(p.RegistryError, "not_found"):
            self.call("/v1/provision-helper", dict(v=1, ip="192.0.2.11"))
        with self.assertRaisesRegex(p.RegistryError, "denied"):
            self.proof(self.device, "helper", self.helper)
        with self.assertRaisesRegex(p.RegistryError, "not_found"):
            self.call("/v1/lease", self.proof(self.device, "lease", "192.0.2.11"))

    def test_disabled_device_and_helper_do_not_receive_new_leases(self):
        result = self.register()
        proof = self.proof(self.device, "lease", "192.0.2.10")
        self.store.set_device(result["device_id"], False)
        with self.assertRaisesRegex(p.RegistryError, "denied"):
            self.call("/v1/lease", proof)
        with self.assertRaisesRegex(p.RegistryError, "denied"):
            self.call("/v1/register", self.proof(self.device, "register", ""))
        self.store.set_device(result["device_id"], True)
        self.store.provision_helper("192.0.2.10", 8444, "ab" * 32, self.agent.public_key(), enabled=False)
        with self.assertRaisesRegex(p.RegistryError, "not_found"):
            self.call("/v1/lease", self.proof(self.device, "lease", "192.0.2.10"))
        config = self.call("/v1/helper-config", self.proof(self.agent, "helper", self.helper))
        self.assertFalse(p.verify_helper_config(config, self.registry.public_key(), now=1000)["enabled"])

    def test_challenge_and_registration_tables_are_bounded(self):
        for _ in range(4):
            self.proof(self.device, "register", "")
        with patch("helper_registry.MAX_CHALLENGES", 4), self.assertRaisesRegex(p.RegistryError, "rate_limited"):
            self.proof(self.device, "register", "")
        self.now += 61
        self.register()
        second = ec.generate_private_key(ec.SECP256R1())
        with patch("helper_registry.MAX_DEVICES", 1):
            with self.assertRaisesRegex(p.RegistryError, "rate_limited"):
                self.call("/v1/register", self.proof(second, "register", ""))

    def test_capacity_gc_preserves_active_devices_and_revocation_tombstones(self):
        keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(4)]
        ids = [self.store.register(key.public_key(), 1000) for key in keys[:3]]
        self.store.set_device(ids[1], False)
        self.store.require_device(ids[2], touch=1950)
        with patch("helper_registry.MAX_DEVICES", 3):
            self.store.register(keys[3].public_key(), 2000)
        with self.assertRaisesRegex(p.RegistryError, "device_not_registered"):
            self.store.require_device(ids[0])
        with self.assertRaisesRegex(p.RegistryError, "denied"):
            self.store.register(keys[1].public_key(), 2000)
        self.store.require_device(ids[2])
        self.now = 2000
        challenge = self.proof(keys[2], "lease", "192.0.2.10")
        with self.store._connect() as db:
            self.assertEqual(1950, db.execute("SELECT last_seen FROM devices WHERE id=?", (ids[2],)).fetchone()[0])
        self.call("/v1/lease", challenge)
        with self.store._connect() as db:
            self.assertEqual(2000, db.execute("SELECT last_seen FROM devices WHERE id=?", (ids[2],)).fetchone()[0])

    def test_actual_10000_record_capacity_recovers_after_idle_window(self):
        raw = p.public_key_der(self.device.public_key())
        # Populate the actual production bound without 10,000 filesystem commits.
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany("INSERT INTO devices VALUES(?,?,1,?,?)",
                           ((format(index, "064x"), raw, 1000, 1000) for index in range(10000)))
            db.commit()
        with self.assertRaisesRegex(p.RegistryError, "rate_limited"):
            self.store.register(self.device.public_key(), 1900)
        identifier = self.store.register(self.device.public_key(), 1901)
        self.assertEqual(p.device_id(self.device.public_key()), identifier)
        with self.store._connect() as db:
            self.assertEqual(1, db.execute("SELECT COUNT(*) FROM devices").fetchone()[0])

    def test_limiter_is_bounded_and_recovers_after_window(self):
        limiter = RateLimiter(maximum=3, per_ip=2)
        self.assertTrue(limiter.admit("192.0.2.1", 0))
        self.assertTrue(limiter.admit("192.0.2.1", 0))
        self.assertFalse(limiter.admit("192.0.2.1", 0))
        self.assertTrue(limiter.admit("192.0.2.2", 0))
        self.assertFalse(limiter.admit("192.0.2.3", 0))
        self.assertEqual(3, len(limiter.events))
        self.assertTrue(limiter.admit("192.0.2.3", 61))
        self.assertEqual({"192.0.2.3": 1}, limiter.counts)

    def test_loopback_http_backend_safe_json_and_request_bounds(self):
        with self.assertRaisesRegex(p.RegistryError, "loopback_required"):
            RegistryHTTPServer(("0.0.0.0", 0), self.service)
        server = RegistryHTTPServer(("127.0.0.1", 0), self.service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            connection.request("POST", "/v1/helper", p.json_bytes(dict(v=1, ip="192.0.2.10")), {"Content-Type": "application/json"})
            response = connection.getresponse()
            self.assertEqual(200, response.status)
            self.assertEqual("no-store", response.getheader("Cache-Control"))
            p.verify_descriptor(p.parse_json(response.read()), self.registry.public_key(), "192.0.2.10", now=1000)
            connection.close()
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            # A huge declared body must be rejected before waiting for or allocating it.
            connection.putrequest("POST", "/v1/helper")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "999999999")
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(400, response.status)
            self.assertEqual({"v": 1, "error": "invalid_data"}, p.parse_json(response.read()))
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
