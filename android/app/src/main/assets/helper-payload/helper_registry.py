#!/usr/bin/env python3
"""Managed Helper registry. Serve only behind the owner's CA-validated HTTPS.

Device enrollment is deliberately public and automatic, not hardware identity.
Helper enrollment needs a registry-initiated strict CA/IP callback or a local
administrator operation. A registered device cannot supply the accepted pin.
This server has no access to any Helper's legacy global bearer token.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import threading
import time

from cryptography.hazmat.primitives import serialization

from helper_pairing import PairingStore
from proxy.registry_protocol import (
    ACCESS, CHALLENGE_TTL, CONFIG_CONTEXT, DESCRIPTOR_CONTEXT, DEVICE_CONTEXT,
    LEASE_TTL, MAX_JSON, PROTOCOL, RegistryError, b64decode, b64encode, canonical_ip,
    decode_public_key, device_id, issue_lease, json_bytes, parse_json, proof_payload,
    public_key_der, sign_envelope, verify_bytes,
)

MAX_DEVICES = 10000
MAX_HELPERS = 1024
MAX_CHALLENGES = 2048


class RegistryStore(PairingStore):
    """Reuse the existing private SQLite path/ownership/sidecar safeguards."""
    def __init__(self, path: str | Path):
        super().__init__(path)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY, public_key BLOB NOT NULL, approved INTEGER NOT NULL,
                    created INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS helpers (
                    id TEXT PRIMARY KEY, ip TEXT UNIQUE NOT NULL, port INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL, agent_key BLOB NOT NULL, enabled INTEGER NOT NULL,
                    rollback_disabled INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS challenges (
                    id BLOB PRIMARY KEY, device TEXT NOT NULL, purpose TEXT NOT NULL,
                    target TEXT NOT NULL, expires INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS challenge_expiry ON challenges(expires);
                CREATE INDEX IF NOT EXISTS challenge_device ON challenges(device);
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(devices)")}
            if "last_seen" not in columns:
                db.execute("ALTER TABLE devices ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0")
            db.execute("UPDATE devices SET last_seen=created WHERE last_seen=0")
            db.execute("CREATE INDEX IF NOT EXISTS device_gc ON devices(approved,last_seen)")
            helper_columns = {row[1] for row in db.execute("PRAGMA table_info(helpers)")}
            if "rollback_disabled" not in helper_columns:
                db.execute("ALTER TABLE helpers ADD COLUMN rollback_disabled INTEGER NOT NULL DEFAULT 0")

    def register(self, key, now: int) -> str:
        identifier = device_id(key)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT approved FROM devices WHERE id=?", (identifier,)).fetchone()
            if old is not None:
                if not old[0]:
                    raise RegistryError("denied")
                db.execute("UPDATE devices SET last_seen=? WHERE id=?", (now, identifier))
            else:
                if db.execute("SELECT COUNT(*) FROM devices").fetchone()[0] >= MAX_DEVICES:
                    # Active leases last at most 600s. Only approved identities
                    # idle beyond that window+margin may disappear; revoked
                    # tombstones must never be silently re-enabled by re-register.
                    db.execute("DELETE FROM devices WHERE approved=1 AND last_seen<?", (now - 900,))
                    if db.execute("SELECT COUNT(*) FROM devices").fetchone()[0] >= MAX_DEVICES:
                        raise RegistryError("rate_limited")
                db.execute("INSERT INTO devices(id,public_key,approved,created,last_seen) VALUES(?,?,1,?,?)",
                           (identifier, public_key_der(key), now, now))
            db.commit()
        return identifier

    def approved(self, identifier: str) -> bool:
        with self._connect() as db:
            row = db.execute("SELECT approved FROM devices WHERE id=?", (identifier,)).fetchone()
            return row is not None and row[0] == 1

    def require_device(self, identifier: str, *, touch: int | None = None):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT approved FROM devices WHERE id=?", (identifier,)).fetchone()
            if row is None:
                raise RegistryError("device_not_registered")
            if not row[0]:
                raise RegistryError("denied")
            if touch is not None:
                db.execute("UPDATE devices SET last_seen=? WHERE id=? AND approved=1", (touch, identifier))
            db.commit()

    def set_device(self, identifier: str, approved: bool) -> None:
        if not isinstance(identifier, str) or len(identifier) != 64 or type(approved) is not bool:
            raise RegistryError("invalid_data")
        with self._connect() as db:
            db.execute("UPDATE devices SET approved=? WHERE id=?", (int(approved), identifier))

    def provision_helper(self, ip: str, port: int, fingerprint: str, agent_key, *, enabled: bool = True) -> str:
        """Trusted local-admin API only. It is intentionally absent from HTTP."""
        ip = canonical_ip(ip)
        raw_key = public_key_der(agent_key)
        # Validate admin inputs with the same strict descriptor schema as clients.
        if (type(port) is not int or not 1 <= port <= 65535 or not isinstance(fingerprint, str)
                or len(fingerprint) != 64 or any(ch not in "0123456789abcdef" for ch in fingerprint)
                or type(enabled) is not bool):
            raise RegistryError("invalid_data")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT id FROM helpers WHERE ip=?", (ip,)).fetchone()
            if row:
                identifier = row[0]
                db.execute("UPDATE helpers SET port=?,fingerprint=?,agent_key=?,enabled=?,rollback_disabled=0 WHERE id=?",
                           (port, fingerprint, raw_key, int(enabled), identifier))
            else:
                if db.execute("SELECT COUNT(*) FROM helpers").fetchone()[0] >= MAX_HELPERS:
                    raise RegistryError("rate_limited")
                identifier = b64encode(secrets.token_bytes(16))
                db.execute("INSERT INTO helpers(id,ip,port,fingerprint,agent_key,enabled,rollback_disabled) VALUES(?,?,?,?,?,?,0)",
                           (identifier, ip, port, fingerprint, raw_key, int(enabled)))
            db.commit()
        return identifier

    def helper(self, *, ip: str | None = None, identifier: str | None = None, include_disabled=False) -> dict:
        with self._connect() as db:
            if ip is not None:
                row = db.execute("SELECT * FROM helpers WHERE ip=?", (canonical_ip(ip),)).fetchone()
            else:
                row = db.execute("SELECT * FROM helpers WHERE id=?", (identifier,)).fetchone()
        if row is None or (not include_disabled and not row[5]):
            raise RegistryError("not_found")
        return dict(helper_id=row[0], ip=row[1], port=row[2], fingerprint=row[3], agent_key=row[4], enabled=bool(row[5]), rollback_disabled=bool(row[6]))

    def challenge(self, key, purpose: str, target: str, now: int) -> dict:
        nonce = b64encode(secrets.token_bytes(32))
        proof_payload(key, purpose, target, nonce)
        identifier = device_id(key)
        if purpose in {"lease", "enroll"}:
            self.require_device(identifier)
        if purpose == "enroll":
            from helper_enrollment import public_ip
            if target != public_ip(target):
                raise RegistryError("invalid_ip")
        if purpose in {"helper", "helper-disable"}:
            helper = self.helper(identifier=target, include_disabled=True)
            if helper["agent_key"] != public_key_der(key):
                raise RegistryError("denied")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM challenges WHERE expires<=?", (now,))
            if db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] >= MAX_CHALLENGES:
                raise RegistryError("rate_limited")
            db.execute("INSERT INTO challenges VALUES(?,?,?,?,?)",
                       (hashlib.sha256(b64decode(nonce, 32)).digest(), identifier, purpose, target, now + CHALLENGE_TTL))
            db.commit()
        return dict(v=1, challenge=nonce, expires_at=now + CHALLENGE_TTL)

    def consume_proof(self, value: dict, purpose: str, now: int):
        if set(value) != {"v", "public_key", "purpose", "target", "challenge", "signature"} or value["purpose"] != purpose:
            raise RegistryError("invalid_data")
        key = decode_public_key(value["public_key"])
        payload = proof_payload(key, purpose, value["target"], value["challenge"])
        digest = hashlib.sha256(b64decode(value["challenge"], 32)).digest()
        # Public keys are public. Unauthenticated requests must neither consume
        # another caller's pending proof nor exhaust an agent-specific quota.
        verify_bytes(key, DEVICE_CONTEXT, payload, b64decode(value["signature"], maximum=72))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT device,purpose,target,expires FROM challenges WHERE id=?", (digest,)).fetchone()
            if row is None or row[:3] != (device_id(key), purpose, value["target"]) or row[3] <= now:
                raise RegistryError("denied")
            db.execute("DELETE FROM challenges WHERE id=?", (digest,))
            db.commit()  # Only a valid matching proof may atomically consume it.
        return key

    def provision_verified_helper(self, proof: dict) -> dict:
        """Called only after the registry's own strict CA-IP callback verifies."""
        key = public_key_der(decode_public_key(proof["agent_public_key"]))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT id,port,fingerprint,agent_key,enabled,rollback_disabled FROM helpers WHERE ip=?", (proof["ip"],)).fetchone()
            if row is not None:
                if not row[4]:
                    if not row[5] or row[3] != key:
                        raise RegistryError("denied")
                    # Owner's failed setup may have lost its staged TLS leaf.
                    # Fresh CA/IP proof plus the retained SAME agent identity is
                    # required to recover this explicitly marked rollback state.
                    db.execute("UPDATE helpers SET port=?,fingerprint=?,enabled=1,rollback_disabled=0 WHERE id=?",
                               (proof["port"], proof["fingerprint"], row[0]))
                elif row[1:4] != (proof["port"], proof["fingerprint"], key):
                    raise RegistryError("conflict")
            else:
                if db.execute("SELECT COUNT(*) FROM helpers").fetchone()[0] >= MAX_HELPERS:
                    raise RegistryError("rate_limited")
                identifier = b64encode(secrets.token_bytes(16))
                db.execute("INSERT INTO helpers(id,ip,port,fingerprint,agent_key,enabled,rollback_disabled) VALUES(?,?,?,?,?,1,0)",
                           (identifier, proof["ip"], proof["port"], proof["fingerprint"], key))
            db.commit()
        return self.helper(ip=proof["ip"])

    def disable_helper(self, identifier: str, agent_key):
        with self._connect() as db:
            result = db.execute("UPDATE helpers SET enabled=0,rollback_disabled=1 WHERE id=? AND agent_key=? AND (enabled=1 OR rollback_disabled=1)",
                                (identifier, public_key_der(agent_key)))
            if result.rowcount != 1:
                raise RegistryError("denied")


class RateLimiter:
    def __init__(self, *, maximum=600, per_ip=60):
        self.maximum = maximum
        self.per_ip = per_ip
        self.events = deque()
        self.counts = {}
        self.lock = threading.Lock()

    def admit(self, peer: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self.lock:
            while self.events and self.events[0][0] <= now - 60:
                _, old = self.events.popleft()
                self.counts[old] -= 1
                if not self.counts[old]:
                    del self.counts[old]
            if len(self.events) >= self.maximum or self.counts.get(peer, 0) >= self.per_ip:
                return False
            self.events.append((now, peer))
            self.counts[peer] = self.counts.get(peer, 0) + 1
            return True


class RegistryService:
    def __init__(self, store: RegistryStore, signing_key, *, clock=time.time, ownership_verifier=None):
        public_key_der(signing_key.public_key())
        self.store = store
        self.signing_key = signing_key
        self.clock = clock
        self.limiter = RateLimiter()
        if ownership_verifier is None:
            from helper_enrollment import IPOwnershipVerifier
            ownership_verifier = IPOwnershipVerifier(clock=clock)
        self.ownership_verifier = ownership_verifier

    def descriptor(self, helper: dict, now: int) -> dict:
        payload = {key: helper[key] for key in ("helper_id", "ip", "port", "fingerprint")}
        payload.update(v=1, iat=now, exp=now + LEASE_TTL, protocol=PROTOCOL, access=ACCESS)
        return sign_envelope(payload, self.signing_key, context=DESCRIPTOR_CONTEXT)

    def dispatch(self, path: str, raw: bytes, *, peer="127.0.0.1") -> dict:
        if not self.limiter.admit(canonical_ip(peer)):
            raise RegistryError("rate_limited")
        now = int(self.clock())
        value = parse_json(raw)
        if path == "/v1/challenge":
            if set(value) != {"v", "public_key", "purpose", "target"}:
                raise RegistryError("invalid_data")
            return self.store.challenge(decode_public_key(value["public_key"]), value["purpose"], value["target"], now)
        if path == "/v1/helper":
            if set(value) != {"v", "ip"}:
                raise RegistryError("invalid_data")
            return self.descriptor(self.store.helper(ip=value["ip"]), now)
        purposes = {"/v1/register": "register", "/v1/lease": "lease", "/v1/helper-config": "helper", "/v1/enroll-helper": "enroll", "/v1/helper-disable": "helper-disable"}
        if path not in purposes:
            raise RegistryError("not_found")
        purpose = purposes[path]
        key = self.store.consume_proof(value, purpose, now)
        identifier = device_id(key)
        if purpose == "register":
            self.store.register(key, now)
            return dict(v=1, device_id=identifier, access=ACCESS)
        if purpose in {"lease", "enroll"}:
            self.store.require_device(identifier, touch=now)
        if purpose == "enroll":
            proof = self.ownership_verifier.verify(value["target"])
            if proof["ip"] != value["target"]:
                raise RegistryError("denied")
            helper = self.store.provision_verified_helper(proof)
            return self.descriptor(helper, now)
        if purpose == "lease":
            helper = self.store.helper(ip=value["target"])
            return dict(v=1, descriptor=self.descriptor(helper, now), token=issue_lease(
                self.signing_key, helper["helper_id"], identifier, helper["fingerprint"], now=now))
        helper = self.store.helper(identifier=value["target"], include_disabled=True)
        if helper["agent_key"] != public_key_der(key):
            raise RegistryError("denied")
        if purpose == "helper-disable":
            self.store.disable_helper(helper["helper_id"], key)
            helper["enabled"] = False
        payload = {key: helper[key] for key in ("helper_id", "ip", "port", "fingerprint", "enabled")}
        payload.update(v=1, iat=now, exp=now + LEASE_TTL, max_device_connections=32, access=ACCESS)
        return sign_envelope(payload, self.signing_key, context=CONFIG_CONTEXT)


class RegistryHTTPServer(ThreadingHTTPServer):
    """Bounded loopback-only backend; HTTPS is terminated by a trusted owner proxy."""
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, service: RegistryService, *, trusted_proxy=False):
        if not ipaddress.ip_address(address[0]).is_loopback:
            raise RegistryError("loopback_required")
        self.service = service
        self.trusted_proxy = trusted_proxy
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, RegistryRequestHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # No traceback may expose credential-bearing request objects.


class RegistryRequestHandler(BaseHTTPRequestHandler):
    server_version = "TGRegistry"
    sys_version = ""

    def setup(self):
        self.request.settimeout(5)
        super().setup()
        self._setup_deadline = time.monotonic() + 5
        self._deadline = threading.Timer(5, self._expire_request)
        self._deadline.daemon = True
        self._deadline.start()

    def _expire_request(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        self._deadline.cancel()
        super().finish()

    def log_message(self, format, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        raw = json_bytes(dict(v=1, error="invalid_request"))
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def parse_request(self):
        if not super().parse_request():
            return False
        if sum(len(key) + len(value) + 4 for key, value in self.headers.items()) > MAX_JSON:
            self.send_error(431)
            return False
        return True

    def do_POST(self):
        code = 200
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                    or not 1 <= int(lengths[0]) <= MAX_JSON or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get_content_type() != "application/json"):
                raise RegistryError("invalid_data")
            peer = self.client_address[0]
            if self.server.trusted_proxy:
                peers = self.headers.get_all("X-Real-IP", [])
                if len(peers) != 1:
                    raise RegistryError("invalid_data")
                peer = canonical_ip(peers[0])
            body = self.rfile.read(int(lengths[0]))
            if len(body) != int(lengths[0]):
                raise RegistryError("invalid_data")
            if time.monotonic() >= self._setup_deadline:
                raise RegistryError("unavailable")
            if self.path == "/v1/enroll-helper":
                self._deadline.cancel()
                self._deadline = threading.Timer(10, self._expire_request)
                self._deadline.daemon = True
                self._deadline.start()
            result = self.server.service.dispatch(self.path, body, peer=peer)
        except RegistryError as error:
            reason = str(error)
            if reason not in {"not_found", "rate_limited", "invalid_data", "invalid_ip", "conflict", "unavailable", "device_not_registered"}:
                reason = "denied"
            code = {"not_found": 404, "rate_limited": 429, "invalid_data": 400, "invalid_ip": 400, "conflict": 409, "unavailable": 503}.get(reason, 403)
            result = dict(v=1, error=reason)
        except (ValueError, TypeError, OSError, sqlite3.Error):
            code, result = 503, dict(v=1, error="unavailable")
        raw = json_bytes(result)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)


def load_private_key(path: Path):
    for component in path.parents:
        if component.is_symlink():
            raise RegistryError("unsafe_private_key")
    PairingStore._private(path)
    if path.stat().st_size > 4096:
        raise RegistryError("invalid_key")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        public_key_der(key.public_key())
        return key
    except (ValueError, TypeError):
        raise RegistryError("invalid_key") from None


def _admin_drop_privileges(user: str):
    if os.name == "nt":
        raise RegistryError("admin_cli_requires_posix_root")
    if os.geteuid() != 0:
        raise RegistryError("admin_cli_requires_posix_root")
    import pwd
    account = pwd.getpwnam(user)
    if account.pw_uid == 0:
        raise RegistryError("dedicated_service_user_required")
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--signing-key", required=True)
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--trusted-proxy", action="store_true", help="owner proxy must overwrite X-Real-IP")
    provision = commands.add_parser("provision-helper")
    provision.add_argument("--service-user", default="tg-registry")
    provision.add_argument("--ip", required=True)
    provision.add_argument("--port", type=int, default=8444)
    provision.add_argument("--fingerprint", required=True)
    provision.add_argument("--agent-public-key", required=True, help="P256 SubjectPublicKeyInfo PEM file")
    provision.add_argument("--disabled", action="store_true")
    revoke = commands.add_parser("disable-device")
    revoke.add_argument("--service-user", default="tg-registry")
    revoke.add_argument("--device-id", required=True)
    args = parser.parse_args()
    if args.command == "serve":
        service = RegistryService(RegistryStore(args.store), load_private_key(Path(args.signing_key)))
        server = RegistryHTTPServer(("127.0.0.1", args.port), service, trusted_proxy=args.trusted_proxy)
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            server.server_close()
        return
    # All externally supplied Helper properties are admitted only by the trusted admin.
    public_key = None
    if args.command == "provision-helper":
        raw = Path(args.agent_public_key).read_bytes()
        if len(raw) > 1024:
            raise RegistryError("invalid_key")
        public_key = serialization.load_pem_public_key(raw)
        public_key_der(public_key)
    _admin_drop_privileges(args.service_user)
    store = RegistryStore(args.store)
    if args.command == "provision-helper":
        identifier = store.provision_helper(args.ip, args.port, args.fingerprint, public_key, enabled=not args.disabled)
        print(json_bytes(dict(v=1, helper_id=identifier)).decode("ascii"))
    else:
        store.set_device(args.device_id, False)


if __name__ == "__main__":
    main()
