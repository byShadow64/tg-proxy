"""Verified IP-only discovery; leases stay in memory, global tokens never arrive."""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from proxy.registry_channel import REGISTRY_URL, REGISTRY_PUBLIC_KEY
from utils.device_identity import DeviceIdentity


class RegistryError(RuntimeError):
    pass


class RegistryCancelled(RegistryError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _decode(value):
    if not isinstance(value, str) or len(value) > 11000 or not value or "=" in value:
        raise RegistryError("invalid_registry_data")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
            raise ValueError()
        return decoded
    except (ValueError, TypeError):
        raise RegistryError("invalid_registry_data") from None


def _object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        if type(value) is not dict:
            raise ValueError()
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise RegistryError("invalid_registry_data") from None


@dataclass(frozen=True)
class HelperLease:
    host: str
    port: int
    fingerprint: str
    token: str = field(repr=False)
    expires_at: int = 0
    helper_id: str = ""

    @property
    def tls_fingerprint(self):
        return self.fingerprint

    @property
    def registry(self):
        return True


class RegistryClient:
    def __init__(self, identity=None, *, base_url=REGISTRY_URL, public_key=REGISTRY_PUBLIC_KEY, ssl_context=None):
        url = urlsplit(base_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise RegistryError("invalid_registry_endpoint")
        self.host, self.port = url.hostname, url.port or 443
        self._authority = url.netloc
        self.identity = identity if identity is not None else DeviceIdentity.load()
        self.key = serialization.load_der_public_key(_decode(public_key))
        if not isinstance(self.key, ec.EllipticCurvePublicKey) or not isinstance(self.key.curve, ec.SECP256R1):
            raise RegistryError("invalid_registry_key")
        self.context = ssl_context or ssl.create_default_context()
        if self.context.verify_mode != ssl.CERT_REQUIRED or not self.context.check_hostname:
            raise RegistryError("unverified_registry_tls")
        self._registered = False
        self._cache = {}
        self._failures = {}
        self._lock = threading.Lock()

    async def _post(self, path, value):
        writer = None
        try:
            reader, writer = await asyncio.open_connection(self.host, self.port, ssl=self.context, server_hostname=self.host, limit=8193)
            raw = _canonical(value)
            request = (f"POST {path} HTTP/1.1\r\nHost: {self._authority}\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n").encode("ascii") + raw
            writer.write(request)
            await writer.drain()
            headers = await reader.readuntil(b"\r\n\r\n")
            if len(headers) > 8192:
                raise RegistryError("invalid_registry_data")
            lines = headers.decode("ascii").split("\r\n")
            status = int(lines[0].split(" ")[1])
            fields = {}
            for line in lines[1:]:
                if line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower()
                    if key in fields:
                        raise RegistryError("invalid_registry_data")
                    fields[key] = val.strip()
            length = int(fields.get("content-length", "-1"))
            if status == 429:
                raise RegistryError("rate_limited")
            if (not lines[0].startswith(("HTTP/1.1 ", "HTTP/1.0 ")) or not 100 <= status <= 599
                    or not 0 <= length <= 8192 or "transfer-encoding" in fields
                    or fields.get("content-type", "").split(";", 1)[0].lower() != "application/json"):
                raise RegistryError("invalid_registry_data")
            data = _object(await reader.readexactly(length))
            if status != 200:
                code = data.get("error")
                if code == "not_found" and path in ("/v1/lease", "/v1/helper"):
                    code = "helper_not_found"
                elif code == "denied":
                    code = "device_denied"
                raise RegistryError(code if code in {"helper_not_found", "rate_limited", "device_denied", "device_not_registered", "invalid_proof"} else "registry_unavailable")
            return data
        except RegistryError:
            raise
        except (OSError, ValueError, UnicodeError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            raise RegistryError("registry_unavailable") from None
        finally:
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), .5)
                except (OSError, asyncio.TimeoutError):
                    pass

    async def _authenticate(self, purpose, target):
        request = {"v": 1, "public_key": self.identity.public_key, "purpose": purpose, "target": target}
        response = await self._post("/v1/challenge", request)
        if set(response) != {"v", "challenge", "expires_at"} or type(response["v"]) is not int or response["v"] != 1:
            raise RegistryError("invalid_registry_data")
        if len(_decode(response["challenge"])) != 32 or type(response["expires_at"]) is not int or not time.time() < response["expires_at"] <= time.time() + 90:
            raise RegistryError("invalid_registry_data")
        proof = {"v": 1, "device_id": self.identity.device_id, "purpose": purpose, "target": target, "challenge": response["challenge"]}
        request.update(challenge=response["challenge"], signature=self.identity.sign(b"TGPROXY_REGISTRY_DEVICE_V1\0" + _canonical(proof)))
        return await self._post("/v1/" + purpose, request)

    def _verify_lease(self, response, host):
        try:
            if set(response) != {"v", "descriptor", "token"} or type(response["v"]) is not int or response["v"] != 1:
                raise ValueError()
            envelope = response["descriptor"]
            if type(envelope) is not dict or set(envelope) != {"v", "payload", "signature"} or type(envelope["v"]) is not int or envelope["v"] != 1:
                raise ValueError()
            payload = _decode(envelope["payload"])
            self.key.verify(_decode(envelope["signature"]), b"TGPROXY_REGISTRY_DESCRIPTOR_V1\0" + payload, ec.ECDSA(hashes.SHA256()))
            descriptor = _object(payload)
            if set(descriptor) != {"v", "helper_id", "ip", "port", "fingerprint", "iat", "exp", "protocol", "access"} or _canonical(descriptor) != payload:
                raise ValueError()
            now = int(time.time())
            if type(descriptor["v"]) is not int or descriptor["v"] != 1 or descriptor["ip"] != host or descriptor["protocol"] != "helper-v2-lease" or descriptor["access"] != "registered-device-public":
                raise ValueError()
            if type(descriptor["port"]) is not int or not 1 <= descriptor["port"] <= 65535 or any(type(descriptor[x]) is not int for x in ("iat", "exp")) or not now - 60 <= descriptor["iat"] <= now + 30 or not now < descriptor["exp"] <= descriptor["iat"] + 600:
                raise ValueError()
            fingerprint = descriptor["fingerprint"]
            if not isinstance(fingerprint, str) or len(fingerprint) != 64 or bytes.fromhex(fingerprint).hex() != fingerprint:
                raise ValueError()
            helper_id = _decode(descriptor["helper_id"])
            if len(helper_id) != 16:
                raise ValueError()
            token = response["token"]
            if not isinstance(token, str) or len(token) > 512:
                raise ValueError()
            prefix, body, signature = token.split(".")
            raw = _decode(body)
            if prefix != "TGL1" or len(raw) != 113:
                raise ValueError()
            self.key.verify(_decode(signature), b"TGPROXY_REGISTRY_LEASE_V1\0" + raw, ec.ECDSA(hashes.SHA256()))
            version, hid, device, pin, issued, expires, _ = struct.unpack(">B16s32s32sQQ16s", raw)
            if version != 1 or hid != helper_id or device.hex() != self.identity.device_id or pin.hex() != fingerprint or not now - 60 <= issued <= now + 30 or not now < expires <= issued + 600 or expires > descriptor["exp"]:
                raise ValueError()
            return HelperLease(host, descriptor["port"], fingerprint, token, expires, descriptor["helper_id"])
        except RegistryError:
            raise
        except Exception:
            raise RegistryError("invalid_registry_data") from None

    def lease(self, host, *, cancelled=lambda: False, force=False):
        host = str(ipaddress.ip_address(host.strip()))
        deadline = time.monotonic() + 12
        while not self._lock.acquire(timeout=.05):
            if cancelled():
                raise RegistryCancelled("cancelled")
            if time.monotonic() >= deadline:
                raise RegistryError("registry_timeout")
        try:
            if cancelled():
                raise RegistryCancelled("cancelled")
            existing = self._cache.get(host)
            if not force and existing and existing.expires_at > time.time() + 30:
                return existing
            failure = self._failures.get(host)
            if not force and failure and time.monotonic() < failure[1]:
                raise RegistryError(failure[0])

            async def register():
                registered = await self._authenticate("register", "")
                if type(registered.get("v")) is not int or registered != {"v": 1, "device_id": self.identity.device_id, "access": "registered-device-public"}:
                    raise RegistryError("invalid_registry_data")
                self._registered = True

            async def operation():
                if not self._registered:
                    await register()
                try:
                    result = await self._authenticate("lease", host)
                except RegistryError as error:
                    # Inactive approved registrations may be reclaimed. Only
                    # this explicit code permits one same-key re-enrollment;
                    # a revoked/denied key never takes this path.
                    if str(error) != "device_not_registered":
                        raise
                    self._registered = False
                    await register()
                    result = await self._authenticate("lease", host)
                return self._verify_lease(result, host)

            async def run():
                task = asyncio.create_task(operation())
                try:
                    while not task.done():
                        if cancelled():
                            raise RegistryCancelled("cancelled")
                        if time.monotonic() >= deadline:
                            raise RegistryError("registry_timeout")
                        await asyncio.wait({task}, timeout=.05)
                    return await task
                finally:
                    if not task.done():
                        task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

            try:
                value = asyncio.run(run())
            except RegistryError as error:
                if not isinstance(error, RegistryCancelled):
                    if len(self._failures) >= 8:
                        self._failures.clear()
                    delay = 60 if str(error) in {"rate_limited", "device_denied"} else 15
                    self._failures[host] = (str(error), time.monotonic() + delay)
                raise
            if cancelled():
                raise RegistryCancelled("cancelled")
            self._failures.pop(host, None)
            if len(self._cache) >= 8:
                self._cache.clear()
            self._cache[host] = value
            return value
        finally:
            self._lock.release()


_client = None
_client_lock = threading.Lock()


def discover_helper(host, *, cancel_event=None, force=False):
    global _client
    with _client_lock:
        if _client is None:
            _client = RegistryClient()
    return _client.lease(host, cancelled=cancel_event.is_set if cancel_event is not None else lambda: False, force=force)
