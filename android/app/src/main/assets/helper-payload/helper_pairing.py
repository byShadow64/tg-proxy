#!/usr/bin/env python3
"""One-use, certificate-bound Helper pairing; the owner issues codes over SSH.

This file is also shipped in the small standalone Helper source payload. It has
no third-party dependencies and never reads or prints the Helper bearer token.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import stat
import sys
import time

MAGIC = b"TGPAIR1"
DENIED = b"PAIR_NO"
CLIENT_CONTEXT = b"TGPROXY_PAIR_CLIENT_V1\0"
SERVER_CONTEXT = b"TGPROXY_PAIR_SERVER_V1\0"
MAX_REQUEST = 1024
MAX_RESPONSE = 4096
MAX_PAYLOAD = 2048
DEFAULT_STORE = "/var/lib/tg-helper/pairing.sqlite3"
DEFAULT_TTL = 300
MAX_TTL = 600
MAX_ACTIVE = 32
MAX_ATTEMPTS = 5
_CODE = re.compile(r"TG1\.([A-Za-z0-9_-]{11})\.([A-Za-z0-9_-]{22})", re.ASCII)


def certificate_digest(pem: str) -> bytes:
    """Hash the first leaf certificate exactly as TLS presents it.

    TLS cert-chain files may contain comments and additional certificates.
    PEM_cert_to_DER_cert accepts only one block, so never pass it a full chain.
    """
    if not isinstance(pem, str):
        raise ValueError("invalid_tls_leaf_certificate")
    match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.DOTALL)
    if match is None:
        raise ValueError("invalid_tls_leaf_certificate")
    leaf = match.group()
    try:
        # Parse X.509 as well as base64; malformed DER must not be fingerprinted.
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=leaf)
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf)).digest()
    except (ValueError, ssl.SSLError, UnicodeError):
        raise ValueError("invalid_tls_leaf_certificate") from None


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64decode(value, size: int | None = None, *, maximum: int = MAX_RESPONSE) -> bytes:
    if (not isinstance(value, str) or not value or len(value) > maximum * 2
            or not re.fullmatch(r"[A-Za-z0-9_-]+", value, re.ASCII)):
        raise ValueError("invalid_pairing_data")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("invalid_pairing_data") from exc
    if len(raw) > maximum or (size is not None and len(raw) != size) or b64encode(raw) != value:
        raise ValueError("invalid_pairing_data")
    return raw


def parse_code(code: str) -> tuple[str, bytes]:
    if not isinstance(code, str) or not (match := _CODE.fullmatch(code)):
        raise ValueError("invalid_pairing_code")
    identifier, secret = match.groups()
    b64decode(identifier, 8)
    b64decode(secret, 16)
    return identifier, hashlib.sha256(code.encode("ascii")).digest()


def json_bytes(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def parse_json(data: bytes, *, maximum: int) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        raise ValueError("invalid_pairing_data")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("invalid_pairing_data")
            result[key] = value
        return result

    try:
        result = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("invalid_pairing_data") from exc
    if not isinstance(result, dict) or type(result.get("v")) is not int or result["v"] != 1:
        raise ValueError("invalid_pairing_data")
    return result


def client_proof(key: bytes, identifier: str, nonce: bytes, certificate: bytes) -> bytes:
    return hmac.digest(key, CLIENT_CONTEXT + identifier.encode("ascii") + b"\0" + nonce + certificate, "sha256")


def server_proof(key: bytes, identifier: str, client_nonce: bytes, server_nonce: bytes,
                 certificate: bytes, payload: bytes) -> bytes:
    return hmac.digest(key, SERVER_CONTEXT + identifier.encode("ascii") + b"\0"
                       + client_nonce + server_nonce + certificate + payload, "sha256")


def parse_request(data: bytes) -> tuple[str, bytes, bytes]:
    value = parse_json(data, maximum=MAX_REQUEST)
    if set(value) != {"v", "id", "nonce", "proof"}:
        raise ValueError("invalid_pairing_data")
    b64decode(value["id"], 8)
    return value["id"], b64decode(value["nonce"], 32), b64decode(value["proof"], 32)


class PairingStore:
    """Private SQLite state. Consume and failed-attempt updates are atomic."""

    def __init__(self, path: str | Path = DEFAULT_STORE):
        self.path = Path(path).absolute()
        parent = self.path.parent
        # Reject symlinks at every existing component, including the state dir.
        for component in reversed((parent, *parent.parents)):
            if component.is_symlink():
                raise ValueError("unsafe_pairing_store")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._private(parent, directory=True)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            self._private(self.path, descriptor=fd)
        finally:
            os.close(fd)
        with self._connect() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS codes (id TEXT PRIMARY KEY, key BLOB NOT NULL, "
                               "expires REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, "
                               "used INTEGER NOT NULL DEFAULT 0)")

    @staticmethod
    def _private(path: Path, *, directory=False, descriptor=None):
        info = os.fstat(descriptor) if descriptor is not None else path.lstat()
        expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not expected or stat.S_ISLNK(info.st_mode):
            raise ValueError("unsafe_pairing_store")
        if os.name != "nt":
            mode = 0o700 if directory else 0o600
            if stat.S_IMODE(info.st_mode) != mode or info.st_uid != os.geteuid():
                raise ValueError("unsafe_pairing_store")
        if not directory and info.st_nlink != 1:
            raise ValueError("unsafe_pairing_store")

    @contextmanager
    def _connect(self):
        self._private(self.path.parent, directory=True)
        self._private(self.path)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                try:
                    self._private(sidecar)
                except FileNotFoundError:
                    pass  # Another transaction finished removing its journal.
        connection = sqlite3.connect(str(self.path), timeout=1, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=1000")
        connection.execute("PRAGMA trusted_schema=OFF")
        try:
            yield connection
        finally:
            connection.close()  # Also rolls back any failed explicit transaction.

    def issue(self, *, ttl: int = DEFAULT_TTL, now: float | None = None) -> str:
        if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
            raise ValueError("invalid_pairing_ttl")
        now = time.time() if now is None else now
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM codes WHERE expires <= ? OR used != 0 OR attempts >= ?", (now, MAX_ATTEMPTS))
            if connection.execute("SELECT COUNT(*) FROM codes").fetchone()[0] >= MAX_ACTIVE:
                raise ValueError("pairing_code_limit")
            code = "TG1." + b64encode(secrets.token_bytes(8)) + "." + b64encode(secrets.token_bytes(16))
            identifier, key = parse_code(code)
            connection.execute("INSERT INTO codes(id,key,expires) VALUES(?,?,?)", (identifier, key, now + ttl))
            connection.commit()
        return code

    def redeem(self, request: bytes, certificate: bytes, token: str, port: int,
               *, now: float | None = None) -> bytes:
        try:
            identifier, nonce, proof = parse_request(request)
        except ValueError:
            return DENIED
        if len(certificate) != 32 or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid_pairing_server_configuration")
        if (not isinstance(token, str) or not 32 <= len(token.encode("utf-8")) <= 512
                or token != token.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in token)):
            raise ValueError("invalid_pairing_server_configuration")
        now = time.time() if now is None else now
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT key,expires,attempts,used FROM codes WHERE id=?", (identifier,)).fetchone()
            if row is None or row[1] <= now or row[2] >= MAX_ATTEMPTS or row[3]:
                connection.commit()
                return DENIED
            key = bytes(row[0])
            if not hmac.compare_digest(proof, client_proof(key, identifier, nonce, certificate)):
                connection.execute("UPDATE codes SET attempts=attempts+1 WHERE id=?", (identifier,))
                connection.commit()
                return DENIED
            # One use even if the client disconnects before it receives the reply.
            connection.execute("UPDATE codes SET used=1 WHERE id=?", (identifier,))
            connection.commit()
        server_nonce = secrets.token_bytes(32)
        payload = json_bytes(dict(v=1, port=port, fingerprint=certificate.hex(), token=token))
        if len(payload) > MAX_PAYLOAD:
            return DENIED
        response = json_bytes(dict(v=1, nonce=b64encode(server_nonce), payload=b64encode(payload),
                                   proof=b64encode(server_proof(key, identifier, nonce, server_nonce, certificate, payload))))
        return response if len(response) <= MAX_RESPONSE else DENIED


def _drop_service_privileges() -> None:
    if os.name == "nt" or os.geteuid() != 0:
        return
    import pwd
    account = pwd.getpwnam("tg-helper")
    os.initgroups(account.pw_name, account.pw_gid)
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue one-use Helper owner codes over SSH (never the bearer token).")
    parser.add_argument("operation", choices=("issue",))
    parser.add_argument("--store", default=DEFAULT_STORE)
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    args = parser.parse_args()
    try:
        _drop_service_privileges()
        os.umask(0o077)
        code = PairingStore(args.store).issue(ttl=args.ttl)
    except (OSError, ValueError, sqlite3.Error, KeyError):
        print("Cannot issue a pairing code. Check service state ownership, TTL and active code limit.", file=sys.stderr)
        return 1
    # The sole credential printed is the freshly issued code, to the SSH owner.
    print(code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
