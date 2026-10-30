"""Sign and atomically publish an allowlisted release over pinned SSH/SFTP.

Import this module to use a private key decrypted by the caller in memory. The
CLI accepts a PEM key outside the checkout; passwords are never CLI arguments.
No remote shell commands are executed and signing keys are never uploaded.
"""
from __future__ import annotations

import argparse
import base64
import errno
import getpass
import hashlib
import hmac
import io
import json
import re
import secrets
import stat
import sys
import threading
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Mapping, Optional
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
ASSET_NAMES = (
    "CHANGELOG.md", "SHA256SUMS.txt", "TgWsProxy_helper.zip", "TgWsProxy_windows.exe",
)
MAX_ASSET_BYTES = {
    "TgWsProxy_windows.exe": 256 * 1024 * 1024,
    "TgWsProxy_helper.zip": 16 * 1024 * 1024,
    "SHA256SUMS.txt": 4096,
    "CHANGELOG.md": 1024 * 1024,
}
HELPER_FILES_1151 = frozenset({
    "helper_server.py", "helper_pairing.py", "deploy_helper.sh", "tg-helper.service", "LICENSE",
    "proxy/__init__.py", "proxy/project.py", "proxy/config.py",
    "proxy/balancer.py", "proxy/utils.py", "proxy/http_transport.py", "docs/RU/Helper.md",
})
HELPER_FILES_1152 = HELPER_FILES_1151 | frozenset({
    "helper_registry.py", "helper_registry_agent.py", "helper_enrollment.py", "deploy_helper_registry.sh",
    "proxy/registry_protocol.py", "proxy/registry_helper.py",
    "helper_requirements.txt", "helper_registry_requirements.txt", "helper_certbot_requirements.txt",
    "tg-helper-registry-agent.service", "tg-helper-registry-agent.timer", "tg-helper-enroll.service",
    "tg-helper-certbot-renew.service", "tg-helper-certbot-renew.timer", "helper_registry_renew.sh",
})
HELPER_FILES = HELPER_FILES_1152 | {"proxy/route_policy.py"}
MAX_MANIFEST_BYTES = 128 * 1024
_TRANSFER_BYTES = 256 * 1024
_CLEANUP_TIMEOUT = 10.0
_PREFETCH_REQUESTS = 16
_PREFETCH_BYTES = _PREFETCH_REQUESTS * 32768  # Paramiko SFTPFile.MAX_REQUEST_SIZE.
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?")
_KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")


class PublicationError(RuntimeError):
    """A non-sensitive error code, safe for CLI and automation output."""

    def __init__(self, code: str):
        self.code = code
        super().__init__("Update publication failed (" + code + ")")


@dataclass(frozen=True)
class PublicationReport:
    version: str
    version_path: str
    uploaded_files: tuple
    reused_version: bool


def transfer_timeout_for_size(byte_count):
    """Default publication budget for both upload and hash readback.

    Only entry points choose this default. publish_release always respects an
    explicitly supplied SSHOptions.command_timeout without increasing it.
    """
    return min(900.0, max(300.0, 60.0 + 2 * byte_count / (128 * 1024)))


def canonical_json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _version_key(version: str):
    match = _VERSION.fullmatch(version) if isinstance(version, str) and len(version) <= 128 else None
    if match is None:
        raise PublicationError("version")
    major, minor, patch = (int(match.group(i)) for i in (1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        suffix = (1, ())
    else:
        parts = prerelease.split(".")
        if any(not p or (p.isdigit() and len(p) > 1 and p.startswith("0")) for p in parts):
            raise PublicationError("version")
        suffix = (0, tuple((0, int(p)) if p.isdigit() else (1, p) for p in parts))
    return major, minor, patch, suffix


def _https_url(value: str, *, base=False) -> str:
    try:
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ValueError
        parsed = urlsplit(value)
        if (any(ord(c) <= 32 or ord(c) == 127 for c in value)
                or parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or (base and parsed.query)
                or "\\" in value or parsed.port == 0):
            raise ValueError
        parsed.hostname.encode("idna")
    except (TypeError, ValueError, UnicodeError):
        raise PublicationError("url") from None
    return value.rstrip("/") if base else value


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise PublicationError("timestamp")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value) -> datetime:
    try:
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
            raise ValueError
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise PublicationError("timestamp") from None


def _windows_version(data: bytes):
    try:
        import pefile
        executable = pefile.PE(data=data, fast_load=True)
        try:
            executable.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            info = executable.VS_FIXEDFILEINFO[0]
            file_version = (info.FileVersionMS >> 16, info.FileVersionMS & 0xffff,
                            info.FileVersionLS >> 16, info.FileVersionLS & 0xffff)
            product_version = (info.ProductVersionMS >> 16, info.ProductVersionMS & 0xffff,
                               info.ProductVersionLS >> 16, info.ProductVersionLS & 0xffff)
            if file_version != product_version:
                raise ValueError
            return file_version
        finally:
            executable.close()
    except Exception:
        raise PublicationError("pe_version") from None


def _validate_helper_zip(data: bytes, *, version: str | None = None):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            names = {"TgWsProxy-helper/" + n for n in HELPER_FILES}
            actual = {i.filename for i in entries}
            # Old immutable releases predate pairing. Their exact old allowlist
            # remains valid; new releases must ship the complete new payload.
            pairing_names = {"TgWsProxy-helper/" + n for n in HELPER_FILES_1151}
            old_names = pairing_names - {"TgWsProxy-helper/helper_pairing.py"}
            historical = version is not None and _version_key(version) < _version_key("1.15.1")
            pre_registry = version is not None and _version_key(version) < _version_key("1.15.2")
            # Preserve the already published 1.15.2 archive. New source
            # packages include route_policy; never rewrite immutable assets.
            pre_route_policy = version is not None and _version_key(version) <= _version_key("1.15.2")
            registry_names = {"TgWsProxy-helper/" + n for n in HELPER_FILES_1152}
            if (len(entries) != len(actual)
                    or (actual != names and not (pre_registry and actual == pairing_names)
                        and not (pre_route_policy and actual == registry_names)
                        and not (historical and actual == old_names))):
                raise ValueError
            if sum(i.file_size for i in entries) > 8 * 1024 * 1024:
                raise ValueError
            for entry in entries:
                if (entry.is_dir() or entry.flag_bits & 1
                        or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)
                        or _PRIVATE_KEY.search(archive.read(entry))):
                    raise ValueError
    except Exception:
        raise PublicationError("helper_archive") from None


def _read_release_files(version: str, files: Mapping) -> dict:
    _version_key(version)
    if not isinstance(files, Mapping) or set(files) != set(ASSET_NAMES):
        raise PublicationError("asset_allowlist")
    result = {}
    for name in ASSET_NAMES:
        path = Path(files[name])
        if (path.name != name or path.is_symlink() or not path.is_file()
                or not 0 < path.stat().st_size <= MAX_ASSET_BYTES[name]):
            raise PublicationError("asset_file")
        data = path.read_bytes()
        if not 0 < len(data) <= MAX_ASSET_BYTES[name]:
            raise PublicationError("asset_file")
        result[name] = data
    expected_version = tuple(int(n) for n in version.split("-", 1)[0].split(".")) + (0,)
    if _windows_version(result["TgWsProxy_windows.exe"]) != expected_version:
        raise PublicationError("pe_version")
    _validate_helper_zip(result["TgWsProxy_helper.zip"], version=version)
    if _PRIVATE_KEY.search(result["CHANGELOG.md"]):
        raise PublicationError("private_material")
    try:
        lines = result["SHA256SUMS.txt"].decode("ascii").splitlines()
        expected = {name: hashlib.sha256(result[name]).hexdigest()
                    for name in ("TgWsProxy_windows.exe", "TgWsProxy_helper.zip")}
        actual = {}
        for line in lines:
            match = re.fullmatch(r"([0-9a-f]{64})  (TgWsProxy_windows\.exe|TgWsProxy_helper\.zip)", line)
            if match is None or match.group(2) in actual:
                raise ValueError
            actual[match.group(2)] = match.group(1)
        if actual != expected:
            raise ValueError
    except (UnicodeDecodeError, ValueError):
        raise PublicationError("checksums") from None
    return result


def build_signed_manifest(version: str, assets: Mapping, base_url: str,
                          private_key: Ed25519PrivateKey, key_id: str,
                          notes: str = "", page_url: Optional[str] = None,
                          *, published_at: Optional[datetime] = None,
                          expires_at: Optional[datetime] = None) -> bytes:
    """Validate four local release files and sign the schema/key-bound payload.

    ``assets`` maps the exact public asset names to local paths. ``private_key``
    is an in-memory Ed25519 key; it is neither serialized nor included in output.
    """
    contents = _read_release_files(version, assets)
    base_url = _https_url(base_url, base=True)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise PublicationError("signing_key")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise PublicationError("key_id")
    if not isinstance(notes, str) or len(notes.encode("utf-8")) > 32 * 1024:
        raise PublicationError("notes")
    published = _utc(published_at or datetime.now(timezone.utc))
    expires = _utc(expires_at or (published + timedelta(days=90)))
    if not published < expires <= published + timedelta(days=90):
        raise PublicationError("expiry")
    version_url = base_url + "/versions/" + version
    payload = {
        "version": version,
        "published_at": _timestamp(published),
        "expires_at": _timestamp(expires),
        "notes": notes,
        "page_url": _https_url(page_url or version_url + "/CHANGELOG.md"),
        "assets": [{"name": name, "url": version_url + "/" + name,
                    "size": len(contents[name]),
                    "sha256": hashlib.sha256(contents[name]).hexdigest()}
                   for name in ASSET_NAMES],
    }
    unsigned = {"schema": 1, "key_id": key_id, "payload": payload}
    signature = base64.b64encode(private_key.sign(canonical_json(unsigned))).decode("ascii")
    result = canonical_json(dict(unsigned, signature=signature)) + b"\n"
    if len(result) > MAX_MANIFEST_BYTES:
        raise PublicationError("manifest_size")
    return result


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _parse_manifest(data: bytes, *, current=False) -> dict:
    try:
        if not isinstance(data, bytes) or not 0 < len(data) <= MAX_MANIFEST_BYTES:
            raise ValueError
        envelope = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json)
        if (not isinstance(envelope, dict)
                or set(envelope) != {"schema", "key_id", "payload", "signature"}
                or type(envelope["schema"]) is not int or envelope["schema"] != 1
                or not isinstance(envelope["key_id"], str)
                or _KEY_ID.fullmatch(envelope["key_id"]) is None
                or len(base64.b64decode(envelope["signature"], validate=True)) != 64):
            raise ValueError
        payload = envelope["payload"]
        if (not isinstance(payload, dict) or set(payload) != {
                "version", "published_at", "expires_at", "notes", "page_url", "assets"}):
            raise ValueError
        _version_key(payload["version"])
        published, expires = (_parse_timestamp(payload[n]) for n in ("published_at", "expires_at"))
        if not published < expires <= published + timedelta(days=90):
            raise ValueError
        if current and (expires <= datetime.now(timezone.utc)
                        or published > datetime.now(timezone.utc) + timedelta(minutes=5)):
            raise ValueError
        if not isinstance(payload["notes"], str) or len(payload["notes"].encode("utf-8")) > 32 * 1024:
            raise ValueError
        _https_url(payload["page_url"])
        entries = payload["assets"]
        if not isinstance(entries, list) or len(entries) != len(ASSET_NAMES):
            raise ValueError
        names = set()
        base = None
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) != {"name", "url", "size", "sha256"}
                    or entry["name"] not in ASSET_NAMES or entry["name"] in names
                    or type(entry["size"]) is not int
                    or not 0 < entry["size"] <= MAX_ASSET_BYTES[entry["name"]]
                    or not isinstance(entry["sha256"], str)
                    or _SHA256.fullmatch(entry["sha256"]) is None):
                raise ValueError
            url = _https_url(entry["url"])
            suffix = "/versions/" + payload["version"] + "/" + entry["name"]
            if not url.endswith(suffix):
                raise ValueError
            candidate = _https_url(url[:-len(suffix)], base=True)
            if base is not None and candidate != base:
                raise ValueError
            base = candidate
            names.add(entry["name"])
        return payload
    except Exception:
        raise PublicationError("manifest") from None


def _remote_root(webroot: str) -> str:
    if (not isinstance(webroot, str) or not webroot.startswith("/")
            or webroot == "/" or len(webroot) > 1024
            or any(ord(c) <= 32 for c in webroot) or "\\" in webroot
            or any(p in (".", "..", "") for p in webroot.split("/")[1:])):
        raise PublicationError("webroot")
    return webroot


def _missing(sftp, path):
    try:
        return sftp.lstat(path)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return None
        raise


def _require_directory(sftp, path):
    metadata = sftp.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode):
        raise PublicationError("remote_directory")


def _prefetched_chunks(source, size, touch):
    """Keep read requests bounded, including when the caller aborts mid-file.

    Paramiko's prefetch worker can wait indefinitely for a free request slot
    after its reader closes. Windows of at most 16 requests let each worker
    finish dispatching without waiting on another read, even on failure.
    """
    count = window_end = 0
    while count < size:
        touch()
        if count == window_end:
            window_end = min(size, count + _PREFETCH_BYTES)
            source.prefetch(file_size=window_end,
                            max_concurrent_requests=_PREFETCH_REQUESTS)
        chunk = source.read(min(_TRANSFER_BYTES, window_end - count))
        if not chunk:
            return
        count += len(chunk)
        yield chunk
    touch()
    # Reject a file that grew after lstat; do not rely only on its old size.
    extra = source.read(1)
    if extra:
        yield extra
    touch()


def _read_remote(sftp, path, *, maximum, touch):
    touch()
    metadata = sftp.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or not 0 <= metadata.st_size <= maximum:
        raise PublicationError("remote_file")
    result = bytearray()
    with sftp.open(path, "rb") as source:
        for chunk in _prefetched_chunks(source, metadata.st_size, touch):
            result.extend(chunk)
            if len(result) > maximum:
                raise PublicationError("remote_file")
    if len(result) != metadata.st_size:
        raise PublicationError("remote_file")
    return bytes(result)


def _remote_hash(sftp, path, entry, touch):
    touch()
    metadata = sftp.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != entry["size"]:
        raise PublicationError("remote_hash")
    digest, count = hashlib.sha256(), 0
    with sftp.open(path, "rb") as source:
        for chunk in _prefetched_chunks(source, metadata.st_size, touch):
            count += len(chunk)
            if count > entry["size"]:
                raise PublicationError("remote_hash")
            digest.update(chunk)
    if count != entry["size"] or not hmac.compare_digest(digest.hexdigest(), entry["sha256"]):
        raise PublicationError("remote_hash")


def _write_remote(sftp, path, data, touch, on_create=None, on_bytes=None):
    touch()
    with sftp.open(path, "wx", bufsize=0) as destination:
        if on_create is not None:
            on_create()
        sftp.chmod(path, 0o644)
        destination.set_pipelined(True)
        for offset in range(0, len(data), _TRANSFER_BYTES):
            touch()
            chunk = data[offset:offset + _TRANSFER_BYTES]
            destination.write(chunk)
            if on_bytes is not None:
                on_bytes(len(chunk))
        # close() drains delayed write statuses. Let it finish before readback
        # or committing metadata, and preserve its errors for normal rollback.
        touch()


def publish_release(options, expected_hostkey, webroot: str, release_files: Mapping,
                    manifest: bytes, *, ssh_private_key=None,
                    trusted_keys: Optional[Mapping[str, str]] = None,
                    emit=None, cancel=None) -> PublicationReport:
    """Publish without shell access; replace latest.json only after readback.

    ``options`` is utils.ssh_setup.SSHOptions. ``expected_hostkey`` is its
    SSHHostKey or an independently verified SHA256 fingerprint. Authenticate
    using ``ssh_private_key`` (Paramiko PKey) or the ephemeral options.password.
    ``trusted_keys`` maps key IDs to base64 raw public keys; embedded production
    keys are used by default. The client verifier runs before any SSH connection.
    """
    # Import only when connecting: signing does not require SSH modules or GUI.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from utils import ssh_setup
    from utils.update_manifest import verify_manifest

    payload = _parse_manifest(manifest, current=True)
    if trusted_keys is None:
        from proxy.update_channel import TRUSTED_UPDATE_KEYS
        trusted_keys = TRUSTED_UPDATE_KEYS
    try:
        verify_manifest(manifest, trusted_keys)
    except Exception:
        raise PublicationError("signature") from None
    version = payload["version"]
    contents = _read_release_files(version, release_files)
    for entry in payload["assets"]:
        if (len(contents[entry["name"]]) != entry["size"]
                or hashlib.sha256(contents[entry["name"]]).hexdigest() != entry["sha256"]):
            raise PublicationError("asset_manifest_mismatch")
    webroot = _remote_root(webroot)
    try:
        ssh_setup._validate_options(options)
    except Exception:
        raise PublicationError("ssh_options") from None
    if isinstance(expected_hostkey, ssh_setup.SSHHostKey):
        expected_fingerprint = expected_hostkey.fingerprint
    else:
        expected_fingerprint = expected_hostkey
    if (not isinstance(expected_fingerprint, str)
            or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", expected_fingerprint) is None):
        raise PublicationError("host_key")
    if ssh_private_key is None and not options.password:
        raise PublicationError("authentication")

    transport = sock = sftp = None
    lock_created = stage_created = latest_created = False
    stage = webroot + "/versions/." + version + "." + secrets.token_hex(12) + ".tmp"
    version_path = webroot + "/versions/" + version
    lock = webroot + "/.publish.lock"
    latest_temp = webroot + "/.latest." + secrets.token_hex(12) + ".json"
    latest = webroot + "/latest.json"
    uploaded = []
    reused = False
    deadline = time.monotonic() + options.command_timeout
    work_complete = False
    stop_watchdog = threading.Event()
    interrupted = []
    watchdog = None
    sent_bytes = 0
    total_bytes = sum(len(data) for data in contents.values())

    def notify(phase, **extra):
        if emit is not None:
            try:
                emit(dict(phase=phase, **extra))
            except Exception:
                pass

    def transferred(count):
        nonlocal sent_bytes
        sent_bytes += count
        notify("uploading", bytes=sent_bytes, total=total_bytes)

    def is_cancelled():
        if cancel is None:
            return False
        try:
            return bool(cancel.is_set() if hasattr(cancel, "is_set") else cancel())
        except Exception:
            return True

    def watch_deadline():
        # SFTP timeouts are per packet, so a slow stream can otherwise outlive
        # the overall deadline. Interrupt only this SFTP channel; cleanup gets
        # a fresh channel on the same already pinned/authenticated transport.
        while not stop_watchdog.wait(min(0.1, max(0.001, deadline - time.monotonic()))):
            reason = "cancelled" if is_cancelled() else "timeout" if time.monotonic() >= deadline else None
            if reason is not None:
                interrupted.append(reason)
                if sftp is not None:
                    try:
                        sftp.get_channel().close()
                    except Exception:
                        pass
                return

    def touch():
        if is_cancelled():
            raise PublicationError("cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PublicationError("timeout")
        if sftp is not None:
            sftp.get_channel().settimeout(max(0.1, min(15, remaining)))

    def own_latest():
        nonlocal latest_created
        latest_created = True

    try:
        watchdog = threading.Thread(target=watch_deadline, name="publisher-deadline", daemon=True)
        watchdog.start()
        touch()
        notify("connecting")
        transport, sock = ssh_setup._connect(options)
        actual = ssh_setup._identity(transport.get_remote_server_key())
        if (not hmac.compare_digest(actual.fingerprint, expected_fingerprint)
                or (isinstance(expected_hostkey, ssh_setup.SSHHostKey)
                    and (actual.key_type != expected_hostkey.key_type
                         or not hmac.compare_digest(actual.key_data, expected_hostkey.key_data)))):
            raise PublicationError("host_key_mismatch")
        touch()
        if ssh_private_key is not None:
            transport.auth_publickey(options.username, ssh_private_key)
        else:
            transport.auth_password(options.username, options.password, fallback=False)
        if not transport.is_authenticated():
            raise PublicationError("authentication")
        touch()
        sftp = ssh_setup._open_sftp(transport, options.connect_timeout)
        for parent in reversed(PurePosixPath(webroot).parents):
            touch()
            _require_directory(sftp, str(parent))
        _require_directory(sftp, webroot)
        touch()
        try:
            sftp.mkdir(lock, mode=0o700)
        except OSError:
            if _missing(sftp, lock) is not None:
                raise PublicationError("busy") from None
            raise
        lock_created = True
        sftp.chmod(lock, 0o700)
        versions = webroot + "/versions"
        if _missing(sftp, versions) is None:
            sftp.mkdir(versions, mode=0o755)
            sftp.chmod(versions, 0o755)
        _require_directory(sftp, versions)
        previous = _missing(sftp, latest)
        if previous is not None:
            old_payload = _parse_manifest(_read_remote(sftp, latest, maximum=MAX_MANIFEST_BYTES, touch=touch))
            if _version_key(old_payload["version"]) > _version_key(version):
                raise PublicationError("downgrade")
        if _missing(sftp, version_path) is not None:
            notify("verifying")
            _require_directory(sftp, version_path)
            if set(sftp.listdir(version_path)) != set(ASSET_NAMES):
                raise PublicationError("immutable_version")
            try:
                for entry in payload["assets"]:
                    _remote_hash(sftp, version_path + "/" + entry["name"], entry, touch)
            except PublicationError as error:
                if error.code in {"cancelled", "timeout"}:
                    raise
                raise PublicationError("immutable_version") from None
            reused = True
        else:
            touch()
            sftp.mkdir(stage, mode=0o700)
            stage_created = True
            sftp.chmod(stage, 0o700)
            for entry in payload["assets"]:
                path = stage + "/" + entry["name"]
                _write_remote(sftp, path, contents[entry["name"]], touch, on_bytes=transferred)
                notify("verifying")
                _remote_hash(sftp, path, entry, touch)
                uploaded.append(entry["name"])
            touch()
            sftp.chmod(stage, 0o755)
            sftp.rename(stage, version_path)
            stage_created = False
        _write_remote(sftp, latest_temp, manifest, touch, on_create=own_latest)
        if _read_remote(sftp, latest_temp, maximum=MAX_MANIFEST_BYTES, touch=touch) != manifest:
            raise PublicationError("manifest_readback")
        touch()
        notify("committing")
        # OpenSSH's posix-rename extension is required. Never remove the old
        # latest.json as a fallback, because that would expose an empty window.
        try:
            sftp.posix_rename(latest_temp, latest)
        except Exception:
            # The server may have committed the atomic rename before its
            # acknowledgement was lost. Preserve immutable files and require
            # read-only verification; do not claim it is unpublished or retry.
            raise PublicationError("publication_unconfirmed") from None
        latest_created = False
        work_complete = True
        notify("published")
        return PublicationReport(version, version_path, tuple(uploaded), reused)
    except PublicationError as error:
        # Preserve the uncertainty of an attempted atomic rename. Otherwise a
        # channel interrupted during readback must not look like corrupt bytes.
        if error.code != "publication_unconfirmed" and (interrupted or is_cancelled() or time.monotonic() >= deadline):
            raise PublicationError(interrupted[0] if interrupted else "cancelled" if is_cancelled() else "timeout") from None
        raise
    except Exception:
        if interrupted or is_cancelled() or time.monotonic() >= deadline:
            raise PublicationError(interrupted[0] if interrupted else "cancelled" if is_cancelled() else "timeout") from None
        raise PublicationError("sftp") from None
    finally:
        stop_watchdog.set()
        if watchdog is not None and watchdog.is_alive():
            watchdog.join(0.5)
        cleanup = None
        cleanup_timer = None
        if sftp is not None and (latest_created or stage_created or lock_created):
            cleanup_deadline = time.monotonic() + _CLEANUP_TIMEOUT
            try:
                # Cleanup has a separate small absolute deadline and never
                # reauthenticates or removes a path owned by another operation.
                cleanup_timer = threading.Timer(_CLEANUP_TIMEOUT, ssh_setup._close_quietly, args=(transport,))
                cleanup_timer.daemon = True
                cleanup_timer.start()
                cleanup = sftp if work_complete else ssh_setup._open_sftp(
                    transport, min(5, _CLEANUP_TIMEOUT))
                operations = []
                if latest_created:
                    operations.append((cleanup.remove, latest_temp))
                if stage_created:
                    operations.extend((cleanup.remove, stage + "/" + name) for name in ASSET_NAMES)
                    operations.append((cleanup.rmdir, stage))
                if lock_created:
                    operations.append((cleanup.rmdir, lock))
                for operation, path in operations:
                    remaining = cleanup_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        cleanup.get_channel().settimeout(min(2, remaining))
                        operation(path)
                    except Exception:
                        pass
            except Exception:
                pass
            finally:
                if cleanup_timer is not None:
                    cleanup_timer.cancel()
                    if cleanup_timer.is_alive():
                        cleanup_timer.join(0.5)
                if cleanup is not sftp:
                    ssh_setup._close_quietly(cleanup)
        for resource in (sftp, transport, sock):
            ssh_setup._close_quietly(resource)


def _external_key_path(value: str) -> Path:
    path = Path(value)
    try:
        path.resolve().relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise PublicationError("key_inside_checkout")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise PublicationError("key_file")
    return path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--timeout", type=float, help="Explicit total transfer seconds; otherwise derive a bounded default from both transfer directions")
    parser.add_argument("--release-dir", type=Path, default=ROOT / "dist" / "release")
    parser.add_argument("--changelog", type=Path, default=ROOT / "CHANGELOG.md")
    parser.add_argument("--notes-file", type=Path, default=ROOT / "docs" / "RELEASE_NOTES.md")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--page-url")
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--signing-key", required=True, help="Ed25519 PEM key outside the checkout")
    parser.add_argument("--ask-key-passphrase", action="store_true")
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--ssh-key", help="SSH private key outside the checkout")
    parser.add_argument("--ask-ssh-key-passphrase", action="store_true")
    parser.add_argument("--ask-ssh-password", action="store_true")
    parser.add_argument("--host-key", required=True, help="Independently verified SHA256:... host key pin")
    parser.add_argument("--webroot", required=True, help="Absolute SFTP path to the public update directory")
    args = parser.parse_args(argv)
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        import paramiko
        from utils.ssh_setup import SSHOptions

        key_path = _external_key_path(args.signing_key)
        passphrase = getpass.getpass("Signing key passphrase: ").encode() if args.ask_key_passphrase else None
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=passphrase)
        files = {n: args.release_dir / n for n in ASSET_NAMES if n != "CHANGELOG.md"}
        files["CHANGELOG.md"] = args.changelog
        manifest = build_signed_manifest(
            args.version, files, args.base_url, private_key, args.key_id,
            notes=args.notes_file.read_text(encoding="utf-8"), page_url=args.page_url)
        if bool(args.ssh_key) == args.ask_ssh_password:
            raise PublicationError("choose_one_ssh_authentication")
        ssh_key = None
        password = ""
        if args.ssh_key:
            ssh_path = _external_key_path(args.ssh_key)
            ssh_passphrase = getpass.getpass("SSH key passphrase: ") if args.ask_ssh_key_passphrase else None
            ssh_key = paramiko.PKey.from_path(ssh_path, passphrase=ssh_passphrase)
        else:
            password = getpass.getpass("SSH password: ")
        transfer_timeout = args.timeout if args.timeout is not None else transfer_timeout_for_size(
            sum(path.stat().st_size for path in files.values()))
        report = publish_release(
            SSHOptions(args.ssh_host, username=args.ssh_user, port=args.ssh_port, password=password,
                       command_timeout=transfer_timeout),
            args.host_key, args.webroot, files, manifest, ssh_private_key=ssh_key,
            trusted_keys={args.key_id: base64.b64encode(private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")})
        print("Published " + report.version + " (" + str(len(report.uploaded_files)) + " new assets)")
        return 0
    except PublicationError as error:
        print(str(error), file=sys.stderr)
    except Exception:
        print("Update publication failed (input_or_authentication)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
