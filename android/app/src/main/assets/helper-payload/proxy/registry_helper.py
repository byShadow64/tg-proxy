"""Optional Helper lease authorization. Legacy private-token clients stay intact."""
from __future__ import annotations

import asyncio
from collections import deque
from pathlib import Path
import threading
import time

from helper_pairing import PairingStore
from proxy.registry_protocol import MAX_JSON, RegistryError, parse_json, verify_helper_config, verify_lease

MAX_REGISTERED_MESSAGE_SIZE = 2 * 1024 * 1024
MIN_REGISTERED_MESSAGE_COST = 4 * 1024


class RegistryLeaseAuthorizer:
    def __init__(self, public_key_path: Path, configuration_path: Path,
                 certificate_digest: bytes, *, port: int | None = None, clock=time.time,
                 device_rate=4 * 1024 * 1024, shared_rate=16 * 1024 * 1024,
                 max_registered_connections=32):
        from helper_registry_agent import protected_public_key
        if not isinstance(certificate_digest, bytes) or len(certificate_digest) != 32:
            raise RegistryError("invalid_configuration")
        self.public_key = protected_public_key(Path(public_key_path).absolute())
        self.path = Path(configuration_path).absolute()
        self.fingerprint = certificate_digest.hex()
        self.port = port
        self.clock = clock
        self._counts = {}
        if (type(device_rate) is not int or type(shared_rate) is not int or
                not 65536 <= device_rate <= shared_rate <= 256 * 1024 * 1024 or
                type(max_registered_connections) is not int or not 1 <= max_registered_connections <= 256):
            raise RegistryError("invalid_configuration")
        self.device_rate, self.shared_rate = device_rate, shared_rate
        self.max_registered_connections = max_registered_connections
        self._buckets = {}
        self._closed_until = {}
        self._waiters = deque()
        self._shared_bucket = [self._burst(shared_rate), time.monotonic()]
        self._lock = threading.Lock()
        self._cached_stat = None
        self._cached_envelope = None
        # A stale control plane denies new lease auth, while legacy private clients
        # must still be able to use their existing certificate/global token.

    @staticmethod
    def _burst(rate):
        # Telegram requires one unfragmented binary frame. A complete bounded
        # message must fit an empty bucket, including at a low configured rate.
        return max(MAX_REGISTERED_MESSAGE_SIZE, rate / 4)

    def _configuration(self):
        for component in (self.path.parent, *self.path.parent.parents):
            if component.is_symlink():
                raise RegistryError("unsafe_configuration")
        PairingStore._private(self.path.parent, directory=True)
        PairingStore._private(self.path)
        info = self.path.stat()
        if info.st_size > MAX_JSON:
            raise RegistryError("invalid_configuration")
        stamp = (info.st_mtime_ns, info.st_size, info.st_ino)
        if stamp != self._cached_stat:
            self._cached_envelope = parse_json(self.path.read_bytes())
            self._cached_stat = stamp
        configuration = verify_helper_config(self._cached_envelope, self.public_key, now=self.clock())
        if configuration["fingerprint"] != self.fingerprint or (self.port is not None and configuration["port"] != self.port):
            raise RegistryError("invalid_configuration")
        return configuration

    def acquire(self, token: bytes) -> str:
        """Reserve by registered key, including across multiple refreshed leases."""
        try:
            token_text = token.decode("ascii", errors="strict")
        except (AttributeError, UnicodeError):
            raise RegistryError("invalid_lease") from None
        configuration = self._configuration()
        if not configuration["enabled"]:
            raise RegistryError("denied")
        claims = verify_lease(token_text, self.public_key, helper_id=configuration["helper_id"],
                              fingerprint=self.fingerprint, now=self.clock())
        with self._lock:
            self._prune_buckets(time.monotonic())
            count = self._counts.get(claims.device_id, 0)
            if (count >= configuration["max_device_connections"] or len(self._counts) >= 256 or
                    sum(self._counts.values()) >= self.max_registered_connections or
                    (claims.device_id not in self._buckets and len(self._buckets) >= 256)):
                raise RegistryError("quota")
            self._counts[claims.device_id] = count + 1
            self._closed_until.pop(claims.device_id, None)
            if claims.device_id not in self._buckets:
                self._buckets[claims.device_id] = [self._burst(self.device_rate), time.monotonic()]
        return claims.device_id

    def release(self, identifier: str):
        with self._lock:
            count = self._counts.get(identifier, 0)
            if count <= 1:
                self._counts.pop(identifier, None)
                if identifier in self._buckets:
                    self._closed_until[identifier] = time.monotonic() + self._burst(self.device_rate) / self.device_rate
            else:
                self._counts[identifier] = count - 1

    def _prune_buckets(self, now):
        for identifier, expires in tuple(self._closed_until.items()):
            if expires <= now:
                self._closed_until.pop(identifier, None)
                self._buckets.pop(identifier, None)

    async def throttle_message(self, identifier: str, amount: int):
        """Bill one WS message, including a bounded cost for tiny-message CPU."""
        if type(amount) is not int or not 0 <= amount <= MAX_REGISTERED_MESSAGE_SIZE:
            raise RegistryError("invalid_data")
        await self.throttle(identifier, max(MIN_REGISTERED_MESSAGE_COST, amount))

    async def throttle(self, identifier: str, amount: int):
        """Registered traffic only; shared quota remains effective across new keys.

        Upload admits a whole <=2MiB message before one unfragmented WS send;
        download admits <=64KiB chunks. New keys cannot reset the shared bucket.
        A bounded FIFO admits against both buckets atomically; a stream of small
        downloads cannot indefinitely starve an older whole-message upload.
        Waiting is cancellable by Helper Stop.
        """
        if type(amount) is not int or not 0 <= amount <= MAX_REGISTERED_MESSAGE_SIZE:
            raise RegistryError("invalid_data")
        if not amount:
            return
        waiter = object()
        with self._lock:
            if identifier not in self._counts:
                raise RegistryError("denied")
            # Two relay pumps per admitted connection; no unbounded waiter list.
            if len(self._waiters) >= self.max_registered_connections * 2:
                raise RegistryError("quota")
            self._waiters.append(waiter)
        try:
            while True:
                delay = 0.1
                with self._lock:
                    device = self._buckets.get(identifier)
                    if device is None or identifier not in self._counts:
                        raise RegistryError("denied")
                    if self._waiters[0] is waiter:
                        now = time.monotonic()
                        shared = self._shared_bucket
                        for bucket, rate in ((device, self.device_rate), (shared, self.shared_rate)):
                            bucket[0] = min(self._burst(rate), bucket[0] + (now - bucket[1]) * rate)
                            bucket[1] = now
                        delay = max((amount - device[0]) / self.device_rate, (amount - shared[0]) / self.shared_rate, 0)
                        if delay <= 0:
                            device[0] -= amount
                            shared[0] -= amount
                            self._waiters.popleft()
                            return
                await asyncio.sleep(min(delay, 0.1))
        finally:
            with self._lock:
                try:
                    self._waiters.remove(waiter)
                except ValueError:
                    pass
