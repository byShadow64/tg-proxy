"""Ephemeral unit-test signatures; no production signing material or network."""
import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from utils.update_manifest import canonical_message, verify_manifest

_KEY = Ed25519PrivateKey.generate()
KEYS = {"synthetic-unit-update": base64.b64encode(_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()}


def signed_release(version, digest, size=7, *, name="TgWsProxy_windows.exe", expired=False):
    now = datetime.now(timezone.utc)
    stamp = lambda value: value.isoformat().replace("+00:00", "Z")
    payload = {"version": version, "published_at": stamp(now - timedelta(hours=2)),
               "expires_at": stamp(now + timedelta(hours=-1 if expired else 24)),
               "notes": "Synthetic unit-test release", "page_url": "https://backup.invalid/releases/" + version,
               "assets": [{"name": name, "url": "https://backup.invalid/a.exe", "size": size,
                           "sha256": digest.removeprefix("sha256:")}]}
    value = {"schema": 1, "key_id": "synthetic-unit-update", "payload": payload}
    value["signature"] = base64.b64encode(_KEY.sign(canonical_message(1, value["key_id"], payload))).decode()
    raw = json.dumps(value).encode()
    if expired:
        return raw
    release = verify_manifest(raw, KEYS)
    for asset in release["assets"]:
        asset["_signed_manifest"] = raw
    return release
