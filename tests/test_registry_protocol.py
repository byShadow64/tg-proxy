import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from proxy import registry_protocol as p


class RegistryProtocolTest(unittest.TestCase):
    def setUp(self):
        self.registry = ec.generate_private_key(ec.SECP256R1())
        self.device = ec.generate_private_key(ec.SECP256R1())
        self.helper = p.b64encode(b"h" * 16)
        self.pin = "ab" * 32
        self.now = 1000

    def descriptor(self):
        return dict(v=1, helper_id=self.helper, ip="192.0.2.10", port=8444, fingerprint=self.pin,
                    iat=1000, exp=1600, protocol=p.PROTOCOL, access=p.ACCESS)

    def test_spki_is_canonical_p256_and_round_trips(self):
        encoded = p.encode_public_key(self.device.public_key())
        key = p.decode_public_key(encoded)
        self.assertEqual(p.device_id(key), p.device_id(self.device.public_key()))
        with self.assertRaises(p.RegistryError):
            p.decode_public_key(encoded + "=")
        with self.assertRaises(p.RegistryError):
            p.encode_public_key(ec.generate_private_key(ec.SECP384R1()).public_key())

    def test_proof_binds_nonce_purpose_target_and_key(self):
        challenge = p.b64encode(b"n" * 32)
        request = p.make_device_proof(self.device, "lease", "192.0.2.10", challenge)
        signature = p.b64decode(request["signature"])
        p.verify_bytes(self.device.public_key(), p.DEVICE_CONTEXT,
                       p.proof_payload(self.device.public_key(), "lease", "192.0.2.10", challenge), signature)
        for purpose, target in (("register", ""), ("lease", "192.0.2.11")):
            with self.assertRaises(p.RegistryError):
                p.verify_bytes(self.device.public_key(), p.DEVICE_CONTEXT,
                               p.proof_payload(self.device.public_key(), purpose, target, challenge), signature)

    def test_descriptor_requires_signature_expected_ip_and_exact_fields(self):
        envelope = p.sign_envelope(self.descriptor(), self.registry)
        self.assertEqual(self.pin, p.verify_descriptor(envelope, self.registry.public_key(), "192.0.2.10", now=1000)["fingerprint"])
        with self.assertRaises(p.RegistryError):
            p.verify_descriptor(envelope, self.registry.public_key(), "192.0.2.11", now=1000)
        with self.assertRaises(p.RegistryError):
            p.verify_descriptor(envelope, self.registry.public_key(), "192.0.2.10", now=1600)
        for changes in ({"port": True}, {"exp": 1601}, {"fingerprint": self.pin.upper()}, {"token": "must-not-be-public"}):
            altered = self.descriptor() | changes
            with self.assertRaises(p.RegistryError):
                p.verify_descriptor(p.sign_envelope(altered, self.registry), self.registry.public_key(), "192.0.2.10", now=1000)

    def test_lease_under_512_bytes_and_bound_to_helper_device_certificate(self):
        did = p.device_id(self.device.public_key())
        token = p.issue_lease(self.registry, self.helper, did, self.pin, now=1000)
        self.assertEqual(113, p.LEASE_STRUCT.size)
        self.assertLess(len(token.encode("ascii")), 512)
        claims = p.verify_lease(token, self.registry.public_key(), helper_id=self.helper, device=did, fingerprint=self.pin, now=1000)
        self.assertEqual(1600, claims.exp)
        for arguments in ({"helper_id": p.b64encode(b"z" * 16)}, {"device": "00" * 32}, {"fingerprint": "00" * 32}, {"now": 1600}):
            with self.assertRaises(p.RegistryError):
                p.verify_lease(token, self.registry.public_key(), **({"now": 1000} | arguments))

    def test_signature_domain_separation_and_strict_der(self):
        raw = p.json_bytes(self.descriptor())
        sig = p.sign_bytes(self.registry, p.DESCRIPTOR_CONTEXT, raw)
        for wrong in (sig + b"\0", b"\0" * 64):
            with self.assertRaises(p.RegistryError):
                p.verify_bytes(self.registry.public_key(), p.DESCRIPTOR_CONTEXT, raw, wrong)
        with self.assertRaises(p.RegistryError):
            p.verify_bytes(self.registry.public_key(), p.CONFIG_CONTEXT, raw, sig)

    def test_strict_json_bounds_duplicate_keys_types_and_base64(self):
        for raw in (b'{"v":1,"v":1}', b'{"v":true}', b'{"v":1,"x":NaN}', b'[]', b'x' * 8193):
            with self.assertRaises(p.RegistryError):
                p.parse_json(raw)
        for value in ("Zg=", "Zh", "*", "", 123):
            with self.assertRaises(p.RegistryError):
                p.b64decode(value)

    def test_public_interoperability_vector(self):
        vector = json.loads((Path(__file__).parent / "fixtures/helper_registry_v1.json").read_text())
        key = p.decode_public_key(vector["registry_public_key"])
        descriptor = p.verify_descriptor(vector["descriptor"], key, vector["ip"], now=vector["now"])
        claims = p.verify_lease(vector["lease"], key, helper_id=descriptor["helper_id"],
                                fingerprint=descriptor["fingerprint"], device=vector["device_id"], now=vector["now"])
        self.assertEqual(vector["device_id"], claims.device_id)
        proof = vector["device_proof"]
        device_key = p.decode_public_key(proof["public_key"])
        p.verify_bytes(device_key, p.DEVICE_CONTEXT,
                       p.proof_payload(device_key, proof["purpose"], proof["target"], proof["challenge"]),
                       p.b64decode(proof["signature"]))
