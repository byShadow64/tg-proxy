#!/usr/bin/env python3
"""Helper control-plane agent; trust is provisioned once by authenticated SSH.

The registry URL, central public key, agent private key and Helper ID are local
owner-provisioned inputs. No network response may replace the central key.
"""
from __future__ import annotations

import argparse
from contextlib import suppress
import http.client
import ipaddress
import os
from pathlib import Path
import ssl
import socket
import stat
import tempfile
import threading
import time
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from helper_pairing import PairingStore, certificate_digest
from helper_registry import load_private_key
from proxy.registry_protocol import (
    ACCESS, CHALLENGE_TTL, MAX_JSON, RegistryError, device_id, encode_public_key, json_bytes, make_device_proof,
    parse_json, public_key_der, verify_descriptor, verify_helper_config,
)
from proxy.http_transport import create_connection, response_with_deadline

REQUEST_TIMEOUT = 6.0
ENROLL_REQUEST_TIMEOUT = 12.0
_REQUEST_SLOTS = threading.BoundedSemaphore(4)


def protected_public_key(path: Path):
    for component in (path, *path.parents):
        if component.is_symlink():
            raise RegistryError("unsafe_trust_file")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024:
        raise RegistryError("unsafe_trust_file")
    if os.name != "nt" and (info.st_mode & 0o022 or info.st_uid not in {0, os.geteuid()}):
        raise RegistryError("unsafe_trust_file")
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
        public_key_der(key)
        return key
    except (ValueError, TypeError):
        raise RegistryError("invalid_key") from None


class RegistryTransport:
    """Strict CA HTTPS transport; production has no insecure/testing bypass."""
    def __init__(self, base_url: str, *, cancelled: threading.Event | None = None):
        try:
            parsed = urllib.parse.urlsplit(base_url)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.query or parsed.fragment or len(base_url) > 512):
                raise ValueError()
            parsed.port
        except ValueError:
            raise RegistryError("invalid_registry_url") from None
        self.base_url = base_url.rstrip("/")
        self.parsed = parsed
        self.cancelled = cancelled or threading.Event()

    def request(self, path: str, value: dict) -> dict:
        if path not in {"/v1/challenge", "/v1/helper-config", "/v1/register", "/v1/enroll-helper", "/v1/helper", "/v1/helper-disable"}:
            raise RegistryError("invalid_endpoint")
        return self._exchange("POST", path, json_bytes(value))

    def _exchange(self, method: str, path: str, raw_request: bytes | None) -> dict:
        if self.cancelled.is_set():
            raise RegistryError("cancelled")
        if raw_request is not None and len(raw_request) > MAX_JSON:
            raise RegistryError("invalid_data")
        context = ssl.create_default_context()
        budget = ENROLL_REQUEST_TIMEOUT if path == "/v1/enroll-helper" else REQUEST_TIMEOUT
        connection = http.client.HTTPSConnection(self.parsed.hostname, self.parsed.port or 443,
                                                  timeout=budget, context=context)
        if not _REQUEST_SLOTS.acquire(blocking=False):
            raise RegistryError("rate_limited")
        deadline = time.monotonic() + budget
        def connect(address, timeout, source_address=None):
            try:
                numeric = ipaddress.ip_address(address[0])
            except ValueError:
                return create_connection(address, timeout, source_address, deadline=deadline)
            sock = socket.socket(socket.AF_INET if numeric.version == 4 else socket.AF_INET6, socket.SOCK_STREAM)
            try:
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                sock.connect((str(numeric), address[1]))
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                return sock
            except BaseException:
                sock.close()
                raise
        connection._create_connection = connect
        active_socket = [None]
        deadline_response = response_with_deadline(deadline)
        class Response(deadline_response):
            def __init__(self, sock, *args, **kwargs):
                active_socket[0] = sock
                super().__init__(sock, *args, **kwargs)
        connection.response_class = Response
        done = threading.Event()
        def interrupt():
            while not done.wait(0.05):
                if self.cancelled.is_set() or time.monotonic() >= deadline:
                    current = active_socket[0] or connection.sock
                    if current is not None:
                        with suppress(OSError):
                            current.shutdown(socket.SHUT_RDWR)
                    return
        watcher = threading.Thread(target=interrupt, name="tg-registry-request", daemon=True)
        try:
            watcher.start()
            connection.request(method, self.parsed.path.rstrip("/") + path, body=raw_request,
                               headers={"Content-Type": "application/json", "Accept": "application/json"})
            with connection.getresponse() as response:
                if 300 <= response.status < 400:
                    raise RegistryError("redirect_denied")
                if response.status in {404, 429}:
                    raise RegistryError({404: "not_found", 429: "rate_limited"}[response.status])
                if response.status >= 500:
                    raise RegistryError("unavailable")
                if response.status != 200 or response.headers.get_content_type() != "application/json":
                    raise RegistryError("denied")
                if sum(len(k) + len(v) + 4 for k, v in response.getheaders()) > MAX_JSON:
                    raise RegistryError("invalid_data")
                raw = response.read(MAX_JSON + 1)
        except (http.client.HTTPException, TimeoutError, OSError):
            raise RegistryError("cancelled" if self.cancelled.is_set() else "unavailable") from None
        finally:
            done.set()
            connection.close()
            _REQUEST_SLOTS.release()
        if self.cancelled.is_set():
            raise RegistryError("cancelled")
        return parse_json(raw)


def write_configuration(path: Path, envelope: dict):
    path = path.absolute()
    parent = path.parent
    for component in (parent, *parent.parents):
        if component.is_symlink():
            raise RegistryError("unsafe_configuration")
    PairingStore._private(parent, directory=True)
    if path.exists() or path.is_symlink():
        PairingStore._private(path)
    raw = json_bytes(envelope)
    if len(raw) > MAX_JSON:
        raise RegistryError("invalid_data")
    descriptor, temporary = tempfile.mkstemp(prefix=".registry-", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def refresh_configuration(transport, private_key, registry_key, helper_id: str,
                          fingerprint: str, output: Path, *, now=None) -> dict:
    challenge = transport.request("/v1/challenge", dict(v=1, public_key=encode_public_key(private_key.public_key()),
                                                       purpose="helper", target=helper_id))
    current = time.time() if now is None else now
    if (set(challenge) != {"v", "challenge", "expires_at"} or type(challenge["v"]) is not int or challenge["v"] != 1
            or type(challenge["expires_at"]) is not int or not current < challenge["expires_at"] <= current + CHALLENGE_TTL + 30):
        raise RegistryError("invalid_data")
    proof = make_device_proof(private_key, "helper", helper_id, challenge["challenge"])
    envelope = transport.request("/v1/helper-config", proof)
    configuration = verify_helper_config(envelope, registry_key, now=now)
    if configuration["helper_id"] != helper_id or configuration["fingerprint"] != fingerprint:
        raise RegistryError("invalid_configuration")
    write_configuration(output, envelope)
    return configuration


def _proof_request(transport, private_key, purpose, target, *, now=None):
    challenge = transport.request("/v1/challenge", dict(v=1, public_key=encode_public_key(private_key.public_key()),
                                                       purpose=purpose, target=target))
    current = time.time() if now is None else now
    if (set(challenge) != {"v", "challenge", "expires_at"} or type(challenge["v"]) is not int or challenge["v"] != 1
            or type(challenge["expires_at"]) is not int or not current < challenge["expires_at"] <= current + CHALLENGE_TTL + 30):
        raise RegistryError("invalid_data")
    return make_device_proof(private_key, purpose, target, challenge["challenge"])


def enroll_helper(transport, private_key, registry_key, ip: str, fingerprint: str, output: Path, *, now=None) -> dict:
    from helper_enrollment import public_ip
    ip = public_ip(ip)
    registered = transport.request("/v1/register", _proof_request(transport, private_key, "register", "", now=now))
    if (set(registered) != {"v", "device_id", "access"} or type(registered["v"]) is not int or registered["v"] != 1
            or registered["device_id"] != device_id(private_key.public_key()) or registered["access"] != ACCESS):
        raise RegistryError("invalid_data")
    envelope = transport.request("/v1/enroll-helper", _proof_request(transport, private_key, "enroll", ip, now=now))
    descriptor = verify_descriptor(envelope, registry_key, ip, now=now)
    if descriptor["fingerprint"] != fingerprint:
        raise RegistryError("invalid_configuration")
    refresh_configuration(transport, private_key, registry_key, descriptor["helper_id"], fingerprint, output, now=now)
    return descriptor


def disable_helper(transport, private_key, registry_key, helper_id: str | None, fingerprint: str, output: Path, *, now=None, ip=None):
    if not helper_id:
        if not ip:
            raise RegistryError("invalid_data")
        try:
            descriptor = verify_descriptor(transport.request("/v1/helper", dict(v=1, ip=ip)), registry_key, ip, now=now)
        except RegistryError as error:
            if str(error) == "not_found":
                return None  # Could also mean already disabled. This is NOT proof of absence.
            raise
        if descriptor["fingerprint"] != fingerprint:
            raise RegistryError("invalid_configuration")
        helper_id = descriptor["helper_id"]
    proof = _proof_request(transport, private_key, "helper-disable", helper_id, now=now)
    envelope = transport.request("/v1/helper-disable", proof)
    configuration = verify_helper_config(envelope, registry_key, now=now)
    if configuration["helper_id"] != helper_id or configuration["fingerprint"] != fingerprint or configuration["enabled"]:
        raise RegistryError("invalid_configuration")
    write_configuration(output, envelope)
    return configuration


def generate_agent_key(path: Path):
    path = path.absolute()
    for component in path.parents:
        if component.is_symlink():
            raise RegistryError("unsafe_private_key")
    PairingStore._private(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        return load_private_key(path)  # Never silently replace an installation identity.
    key = ec.generate_private_key(ec.SECP256R1())
    raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry-url")
    parser.add_argument("--registry-public-key")
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--helper-id")
    parser.add_argument("--tls-cert")
    parser.add_argument("--output")
    parser.add_argument("--generate-key", action="store_true")
    parser.add_argument("--enroll", action="store_true")
    parser.add_argument("--disable", action="store_true")
    parser.add_argument("--ip")
    args = parser.parse_args()
    if args.generate_key:
        generate_agent_key(Path(args.private_key))
        return
    if not all((args.registry_url, args.registry_public_key, args.tls_cert, args.output)):
        parser.error("registry URL/trust key, local TLS certificate and output are required")
    transport = RegistryTransport(args.registry_url)
    key = load_private_key(Path(args.private_key))
    registry_key = protected_public_key(Path(args.registry_public_key))
    fingerprint = certificate_digest(Path(args.tls_cert).read_text(encoding="ascii")).hex()
    if args.enroll and args.disable:
        parser.error("enroll and disable are mutually exclusive")
    if args.enroll:
        if not args.ip:
            parser.error("public IP is required for owner-enabled enrollment")
        descriptor = enroll_helper(transport, key, registry_key, args.ip, fingerprint, Path(args.output))
        print(json_bytes(dict(v=1, helper_id=descriptor["helper_id"])).decode("ascii"))
    else:
        if not args.helper_id and not (args.disable and args.ip):
            parser.error("owner-provisioned Helper ID is required")
        if args.disable:
            disable_helper(transport, key, registry_key, args.helper_id, fingerprint, Path(args.output), ip=args.ip)
        else:
            refresh_configuration(transport, key, registry_key, args.helper_id, fingerprint, Path(args.output))


if __name__ == "__main__":
    try:
        main()
    except (RegistryError, OSError, ValueError):
        raise SystemExit("Registry agent refresh failed; check owner-provisioned configuration.") from None
