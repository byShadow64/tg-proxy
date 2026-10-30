"""Real Ed25519 signatures, synthetic data, and no network or private key files."""
import base64
import copy
import json
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from utils import update_manifest as manifest


NOW = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.trusted = {'test-2026': base64.b64encode(self.key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)).decode('ascii')}
        self.payload = {
            'version': '1.14.0', 'published_at': '2026-10-24T11:00:00Z',
            'expires_at': '2027-01-22T11:00:00Z', 'notes': 'Исправления и updates',
            'page_url': 'https://updates.example.invalid/releases/1.14.0',
            'assets': [{'name': 'TgWsProxy_windows.exe',
                        'url': 'https://updates.example.invalid/versions/1.14.0/TgWsProxy_windows.exe',
                        'size': 1234, 'sha256': 'a' * 64}],
        }

    def signed(self, payload=None, **fields):
        envelope = {'schema': 1, 'key_id': 'test-2026', 'payload': payload or self.payload}
        envelope.update(fields)
        envelope['signature'] = base64.b64encode(self.key.sign(manifest.canonical_message(
            envelope['schema'], envelope['key_id'], envelope['payload']))).decode('ascii')
        return json.dumps(envelope, ensure_ascii=False).encode('utf-8')

    def verify(self, raw):
        return manifest.verify_manifest(raw, self.trusted, now=NOW)

    def test_valid_unicode_signed_release_and_metadata(self):
        result = self.verify(self.signed())
        self.assertEqual(result['source'], 'backup')
        self.assertEqual(result['notes'], self.payload['notes'])
        self.assertEqual(result['assets'][0]['digest'], 'sha256:' + 'a' * 64)
        self.assertEqual(result['assets'][0]['size'], 1234)
        self.assertEqual(result['assets'][0]['version'], '1.14.0')
        self.assertNotIn('signature', result)

    def test_payload_schema_and_key_id_are_bound_by_signature(self):
        for mutate in (
            lambda e: e['payload'].update(version='9.0.0'),
            lambda e: e.update(schema=2),
            lambda e: e.update(key_id='other'),
        ):
            envelope = json.loads(self.signed())
            mutate(envelope)
            trusted = {**self.trusted, 'other': self.trusted['test-2026']}
            with self.subTest(envelope=envelope), self.assertRaises(ValueError):
                manifest.verify_manifest(json.dumps(envelope).encode(), trusted, now=NOW)

    def test_untrusted_key_wrong_signature_and_invalid_base64(self):
        for mutate in (
            lambda e: e.update(key_id='unknown'),
            lambda e: e.update(signature=base64.b64encode(b'x' * 64).decode()),
            lambda e: e.update(signature='!@invalid'),
            lambda e: e.update(signature=True),
        ):
            envelope = json.loads(self.signed())
            mutate(envelope)
            with self.subTest(envelope=envelope), self.assertRaises(ValueError):
                self.verify(json.dumps(envelope).encode())

    def test_expired_future_and_malformed_timestamps(self):
        for fields in (
            {'expires_at': '2026-10-24T12:00:00Z'},
            {'published_at': '2026-10-24T12:06:00Z'},
            {'expires_at': '2026-10-24T10:00:00Z'},
            {'published_at': '2026-10-24T11:00:00+00:00'},
            {'published_at': '2026-99-24T11:00:00Z'},
        ):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.verify(self.signed({**self.payload, **fields}))

    def test_strict_schema_version_assets_sizes_and_hashes(self):
        invalid_payloads = []
        for version in ('1.14', 'v1.14.0', '01.14.0', '1.14.0-01', '1.14.0-a..b', True, '1.14.0+build'):
            invalid_payloads.append({**self.payload, 'version': version})
        invalid_payloads.extend(({**self.payload, 'unknown': 'field'}, {**self.payload, 'assets': []}))
        for field, value in (('name', '../TgWsProxy_windows.exe'), ('name', 'other.exe'),
                             ('size', True), ('size', 0), ('size', manifest.MAX_ASSET_BYTES + 1),
                             ('sha256', 'A' * 64), ('sha256', 'a' * 63), ('extra', 1)):
            altered = {**self.payload['assets'][0], field: value}
            invalid_payloads.append({**self.payload, 'assets': [altered]})
        invalid_payloads.append({**self.payload, 'assets': self.payload['assets'] * 2})
        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.verify(self.signed(payload))

    def test_non_https_auth_fragment_and_ambiguous_urls_rejected(self):
        for url in ('http://example.invalid/a', 'file:///tmp/a', 'data:evil',
                    'https://user:password@example.invalid/a', 'https://example.invalid/a#fragment',
                    'https://example.invalid\\@evil/a', 'https://example.invalid:99999/a',
                    'https://example.invalid/a\n', 'https:///empty'):
            for field in ('page_url', 'asset_url'):
                payload = copy.deepcopy(self.payload)
                if field == 'page_url':
                    payload[field] = url
                else:
                    payload['assets'][0]['url'] = url
                with self.subTest(url=url, field=field), self.assertRaises(ValueError):
                    self.verify(self.signed(payload))

    def test_raw_size_duplicate_fields_nan_and_trailing_json_rejected(self):
        raw = self.signed()
        for invalid in (b'x' * (manifest.MAX_MANIFEST_BYTES + 1), b'{}{}', b'{"schema":1,"schema":1}',
                        b'{"schema":NaN}', raw + b'junk'):
            with self.subTest(raw=invalid[:80]), self.assertRaises(ValueError):
                self.verify(invalid)

    def test_semver_never_promotes_a_prerelease_over_stable(self):
        sequence = ['1.13.9', '1.14.0-alpha.2', '1.14.0-alpha.10', '1.14.0-beta', '1.14.0', '1.14.1']
        for index, left in enumerate(sequence):
            for right in sequence[:index]:
                self.assertTrue(manifest.version_gt(left, right))
                self.assertFalse(manifest.version_gt(right, left))
            self.assertFalse(manifest.version_gt(left, left))
