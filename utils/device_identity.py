"""Installation key, never a hardware identifier or a device attestation."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import threading
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

_LOCK = threading.Lock()


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class DeviceIdentity:
    def __init__(self, key):
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("invalid_device_key")
        self._key = key
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_key = encode(public)
        self.device_id = hashlib.sha256(public).hexdigest()

    def sign(self, message: bytes) -> str:
        return encode(self._key.sign(message, ec.ECDSA(hashes.SHA256())))

    @classmethod
    def load(cls, path: Path | None = None):
        if path is None:
            from utils.tray_common import APP_DIR
            path = APP_DIR / "device-identity.json"
        path = Path(path)
        with _LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() or path.is_symlink():
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8192:
                    raise ValueError("unsafe_device_key_file")
                if os.name != "nt" and (info.st_mode & 0o077 or info.st_uid != os.getuid()):
                    raise ValueError("unsafe_device_key_file")
                data = json.loads(path.read_text(encoding="utf-8"))
                if type(data) is not dict or set(data) != {"v", "storage", "key"} or type(data["v"]) is not int or data["v"] != 1:
                    raise ValueError("invalid_device_key_file")
                if os.name == "nt":
                    if data["storage"] != "dpapi":
                        raise ValueError("unprotected_device_key")
                    from utils.secure_storage import unprotect_token
                    raw = unprotect_token(data["key"])
                else:
                    if data["storage"] != "private-file":
                        raise ValueError("invalid_device_key_storage")
                    raw = data["key"]
                key = serialization.load_der_private_key(base64.b64decode(raw, validate=True), None)
                return cls(key)
            identity = cls(ec.generate_private_key(ec.SECP256R1()))
            raw = base64.b64encode(identity._key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode("ascii")
            if os.name == "nt":
                from utils.secure_storage import protect_token
                data = {"v": 1, "storage": "dpapi", "key": protect_token(raw)}
            else:
                data = {"v": 1, "storage": "private-file", "key": raw}
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    json.dump(data, output, separators=(",", ":"))
                    output.flush()
                    os.fsync(output.fileno())
            except BaseException:
                path.unlink(missing_ok=True)
                raise
            return identity
