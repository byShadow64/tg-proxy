"""Domain-separated approval of exact, independently tested release bundles."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from publisher.bundle import canonical_json, revalidate_bundle


TRUSTED_APPROVAL_KEYS = {"tgproxy-2026-01": "/JUuGMEQXZSPxtFaxPZO0W6js51c+ocOXq1WL9Qe1z8="}
DOMAIN = b"TGPROXY_STABLE_RELEASE_APPROVAL_V1\0"
MAX_APPROVAL = 32 * 1024


class TrustError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__("Release approval: " + code)


def approval_file(bundle_id):
    if not isinstance(bundle_id, str) or re.fullmatch(r"[0-9a-f]{64}", bundle_id) is None:
        raise TrustError("approval_identity")
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    return base / "TGProxyPublisher" / "approvals" / (bundle_id + ".json")


def _payload(bundle):
    return {"purpose": "stable-release-publication", "bundle_id": bundle.bundle_id,
            "version": bundle.version, "source_commit": bundle.source_commit,
            "build_commit": bundle.build_commit,
            "source_zip_sha256": bundle.manifest["source_zip_sha256"],
            "assets": dict(bundle.manifest["assets"]),
            "notes_sha256": hashlib.sha256(bundle.notes.encode("utf-8")).hexdigest()}


def approve_bundle(bundle, private_key, key_id):
    """Sign only after the caller explicitly confirms completed testing.

    Loading a bundle never calls this function. No key is read from disk here,
    and approval is returned for the caller to save outside immutable bundles.
    """
    from cryptography.hazmat.primitives import serialization
    try:
        bundle = revalidate_bundle(bundle)
        public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if TRUSTED_APPROVAL_KEYS.get(key_id) != base64.b64encode(public).decode("ascii"):
            raise TrustError("approval_key")
        unsigned = {"schema": 1, "key_id": key_id, "payload": _payload(bundle)}
        signature = private_key.sign(DOMAIN + canonical_json(unsigned))
        return {**unsigned, "signature": base64.b64encode(signature).decode("ascii")}
    except TrustError:
        raise
    except Exception as exc:
        raise TrustError(getattr(exc, "code", "approval_signing_failed")) from None


def _unique(items):
    value = {}
    for key, item in items:
        if key in value:
            raise TrustError("approval_format")
        value[key] = item
    return value


def _read_approval(bundle, approval):
    if approval is not None:
        return approval
    path = bundle.root / "approval.json"
    if not path.exists():
        path = approval_file(bundle.bundle_id)
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or path.is_symlink() or getattr(path, "is_junction", lambda: False)() or meta.st_size > MAX_APPROVAL:
        raise TrustError("approval_file")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def verify_approval(bundle, approval=None, *, trusted_keys=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        bundle = revalidate_bundle(bundle)
        approval = _read_approval(bundle, approval)
        if not isinstance(approval, dict) or set(approval) != {"schema", "key_id", "payload", "signature"} or type(approval["schema"]) is not int or approval["schema"] != 1:
            raise TrustError("approval_format")
        if len(canonical_json(approval)) > MAX_APPROVAL:
            raise TrustError("approval_format")
        keys = TRUSTED_APPROVAL_KEYS if trusted_keys is None else trusted_keys
        key_id = approval["key_id"]
        if not isinstance(key_id, str) or key_id not in keys:
            raise TrustError("approval_key")
        if approval["payload"] != _payload(bundle):
            raise TrustError("approval_identity")
        unsigned = {name: approval[name] for name in ("schema", "key_id", "payload")}
        signature = base64.b64decode(approval["signature"], validate=True)
        if len(signature) != 64:
            raise TrustError("approval_signature")
        Ed25519PublicKey.from_public_bytes(base64.b64decode(keys[key_id], validate=True)).verify(signature, DOMAIN + canonical_json(unsigned))
        return {"verified": True, "key_id": key_id, "bundle_id": bundle.bundle_id,
                "source_commit": bundle.source_commit, "build_commit": bundle.build_commit}
    except FileNotFoundError:
        raise TrustError("approval_required") from None
    except TrustError:
        raise
    except Exception:
        raise TrustError("approval_signature") from None


def load_approval(bundle, approval=None):
    """Return the validated signed envelope, never merely a verification flag."""
    try:
        bundle = revalidate_bundle(bundle)
        approval = _read_approval(bundle, approval)
        verify_approval(bundle, approval)
        return json.loads(canonical_json(approval))
    except FileNotFoundError:
        raise TrustError("approval_required") from None
    except TrustError:
        raise
    except Exception as exc:
        raise TrustError(getattr(exc, "code", "approval_format")) from None
