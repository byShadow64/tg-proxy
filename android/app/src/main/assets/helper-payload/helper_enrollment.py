#!/usr/bin/env python3
"""Explicit owner-enabled, CA-IP-authenticated Helper enrollment endpoint.

It exposes only a signed public descriptor and never reads the legacy token.
The registry callback uses a numeric public IP, strict CA/IP identity, no DNS,
no redirects, at most four requests and an absolute six-second HTTP deadline.
"""
from __future__ import annotations

import argparse
from http.server import ThreadingHTTPServer
import ipaddress
from pathlib import Path
import secrets
import socket
import ssl
import threading
import time
import urllib.parse

from helper_pairing import certificate_digest
from helper_registry import RateLimiter, RegistryHTTPServer, RegistryRequestHandler, load_private_key
from proxy.registry_protocol import (
    ACCESS, ENROLL_CONTEXT, RegistryError, b64decode, b64encode, decode_public_key,
    encode_public_key, json_bytes, parse_json, sign_envelope, verify_envelope,
)


def public_ip(value: str) -> str:
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        raise RegistryError("invalid_ip")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise RegistryError("invalid_ip") from None
    if (not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local
            or getattr(ip, "ipv4_mapped", None) is not None):
        raise RegistryError("invalid_ip")
    return str(ip)


class IPOwnershipVerifier:
    def __init__(self, *, clock=time.time):
        self.clock = clock
        self.slots = threading.BoundedSemaphore(4)

    def verify(self, value: str) -> dict:
        ip = public_ip(value)
        if not self.slots.acquire(blocking=False):
            raise RegistryError("rate_limited")
        try:
            from helper_registry_agent import RegistryTransport
            challenge = b64encode(secrets.token_bytes(32))
            address = "[" + ip + "]" if ":" in ip else ip
            transport = RegistryTransport("https://" + address)
            envelope = transport._exchange("GET", "/.well-known/tgproxy-enroll?challenge=" + challenge, None)
            return self.verify_response(envelope, ip, challenge, now=self.clock())
        finally:
            self.slots.release()

    @staticmethod
    def verify_response(envelope: dict, expected_ip: str, challenge: str, *, now=None) -> dict:
        # Parsing this untrusted public key is not acceptance: both CA-IP TLS and
        # the domain-separated signature must verify before any store operation.
        raw = b64decode(envelope.get("payload"), maximum=4096)
        initial = parse_json(raw)
        key = decode_public_key(initial.get("agent_public_key"))
        value = verify_envelope(envelope, key, context=ENROLL_CONTEXT)
        current = time.time() if now is None else now
        if set(value) != {"v", "ip", "port", "fingerprint", "agent_public_key", "challenge", "iat", "exp", "access"}:
            raise RegistryError("invalid_data")
        b64decode(value["challenge"], 32)
        if (value["ip"] != public_ip(expected_ip) or value["challenge"] != challenge or value["access"] != ACCESS
                or type(value["port"]) is not int or not 1 <= value["port"] <= 65535
                or not isinstance(value["fingerprint"], str) or len(value["fingerprint"]) != 64
                or any(ch not in "0123456789abcdef" for ch in value["fingerprint"])
                or type(value["iat"]) is not int or type(value["exp"]) is not int
                or not 0 <= value["iat"] < value["exp"] <= value["iat"] + 60
                or value["iat"] > current + 30 or value["exp"] <= current):
            raise RegistryError("invalid_data")
        return value


class EnrollmentProof:
    def __init__(self, ip: str, port: int, fingerprint: str, private_key, *, clock=time.time):
        self.ip = public_ip(ip)
        if type(port) is not int or not 1 <= port <= 65535 or len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
            raise RegistryError("invalid_data")
        self.port, self.fingerprint, self.key, self.clock = port, fingerprint, private_key, clock

    def envelope(self, challenge: str) -> dict:
        b64decode(challenge, 32)
        now = int(self.clock())
        return sign_envelope(dict(v=1, ip=self.ip, port=self.port, fingerprint=self.fingerprint,
                                  agent_public_key=encode_public_key(self.key.public_key()), challenge=challenge,
                                  iat=now, exp=now + 60, access=ACCESS), self.key, context=ENROLL_CONTEXT)


class EnrollmentHTTPServer(RegistryHTTPServer):
    """Only the explicit --registry-mode installer starts this TLS/443 listener."""
    def __init__(self, address, proof: EnrollmentProof, tls: ssl.SSLContext):
        self.proof, self.limiter = proof, RateLimiter(maximum=120, per_ip=10)
        self.slots = threading.BoundedSemaphore(4)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        ThreadingHTTPServer.__init__(self, address, EnrollmentHandler)
        self.socket = tls.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def get_request(self):
        request, address = self.socket.accept()
        request.settimeout(5)
        return request, address


class EnrollmentHandler(RegistryRequestHandler):
    def setup(self):
        super().setup()
        try:
            self.request.do_handshake()  # In a bounded worker and under the absolute HTTP deadline.
        except BaseException:
            self._deadline.cancel()
            raise

    def do_POST(self):
        self.send_error(405)

    def do_GET(self):
        try:
            if len(self.path) > 200 or not self.server.limiter.admit(self.client_address[0]):
                raise RegistryError("denied")
            url = urllib.parse.urlsplit(self.path)
            query = urllib.parse.parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
            if url.path != "/.well-known/tgproxy-enroll" or url.fragment or set(query) != {"challenge"} or len(query["challenge"]) != 1:
                raise RegistryError("invalid_data")
            raw = json_bytes(self.server.proof.envelope(query["challenge"][0]))
        except (ValueError, KeyError, TypeError):
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--port", type=int, default=8444)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--tls-cert", required=True)
    parser.add_argument("--https-cert", required=True)
    parser.add_argument("--https-key", required=True)
    args = parser.parse_args()
    proof = EnrollmentProof(args.ip, args.port, certificate_digest(Path(args.tls_cert).read_text(encoding="ascii")).hex(),
                            load_private_key(Path(args.private_key)))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.https_cert, args.https_key)
    server = EnrollmentHTTPServer(("::" if ":" in proof.ip else "0.0.0.0", 443), proof, tls)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
