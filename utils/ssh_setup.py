"""Pinned SSH deployment for the helper wizard; no credentials leave memory.

This module is synchronous so callers can run it in a BackgroundTask. Remote
output is drained with size/time limits, never logged or included in errors.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import ipaddress
import json
import math
import queue
import re
import secrets
import shlex
import socket
import ssl
import stat
import tarfile
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Optional

import paramiko


from utils.helper_payload import HELPER_PAYLOAD_FILES
_PAYLOAD_FILES = frozenset(HELPER_PAYLOAD_FILES)
_MAX_PAYLOAD = 8 * 1024 * 1024
_MAX_OUTPUT = 1024 * 1024
_MAX_RESULT = 4 * 1024
_DNS_SLOTS = threading.BoundedSemaphore(4)
_SUPPORTED_SYSTEM = """set -eu
test "$(uname -s)" = Linux
test -r /etc/os-release
. /etc/os-release
case "$ID" in debian|ubuntu) ;; *) exit 1;; esac
command -v systemctl >/dev/null
command -v timeout >/dev/null
test -d /run/systemd/system
"""


@dataclass(frozen=True)
class SSHOptions:
    host: str
    username: str = "root"
    port: int = 22
    password: str = field(default="", repr=False)
    connect_timeout: float = 15
    command_timeout: float = 300


@dataclass(frozen=True)
class SSHHostKey:
    key_type: str
    key_data: bytes = field(repr=False)
    fingerprint: str


@dataclass(frozen=True)
class DeploymentResult:
    host: str
    port: int
    tls_fingerprint: str
    token: str = field(default="", repr=False)
    registry: bool = False
    helper_id: Optional[str] = None


class SSHSetupError(RuntimeError):
    """A stable, non-sensitive error code for localized wizard feedback."""

    def __init__(self, code: str, stage: str):
        self.code, self.stage = code, stage
        super().__init__(f"SSH setup failed ({code})")


def _validate_options(options: SSHOptions, *, authenticate=False) -> None:
    if not isinstance(options, SSHOptions):
        raise SSHSetupError("options", "connect")
    if (not isinstance(options.host, str) or not options.host
            or len(options.host) > 253
            or any(character.isspace() or ord(character) < 32 for character in options.host)
            or any(character in options.host for character in "/\\\x00")):
        raise SSHSetupError("options", "connect")
    if (not isinstance(options.port, int) or isinstance(options.port, bool)
            or not 1 <= options.port <= 65535):
        raise SSHSetupError("options", "connect")
    if (not isinstance(options.username, str) or not options.username
            or len(options.username) > 128
            or any(ord(character) < 32 for character in options.username)):
        raise SSHSetupError("options", "connect")
    for value in (options.connect_timeout, options.command_timeout):
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise SSHSetupError("options", "connect")
    if authenticate and (not isinstance(options.password, str) or not options.password):
        raise SSHSetupError("authentication", "connect")


def _fingerprint(data: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")


def _identity(key) -> SSHHostKey:
    data = key.asbytes()
    return SSHHostKey(key.get_name(), data, _fingerprint(data))


def _close_quietly(resource):
    if resource is not None:
        try:
            resource.close()
        except Exception:
            pass


def _resolve_addresses(host, port, deadline):
    """Bound caller wait and resolver growth when the OS DNS call is stuck.

    A timed-out getaddrinfo cannot be forcibly killed. Its daemon retains its
    slot until it really finishes; no replacement worker is created meanwhile.
    """
    slots = _DNS_SLOTS
    if not slots.acquire(blocking=False):
        raise TimeoutError("SSH resolver capacity is busy")
    result = queue.Queue(maxsize=1)

    def resolve():
        try:
            addresses = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
            result.put((True, tuple(addresses[:32])))
        except BaseException as error:
            result.put((False, error))
        finally:
            slots.release()

    try:
        worker = threading.Thread(target=resolve, name="tg-ssh-dns", daemon=True)
        worker.start()
    except BaseException:
        slots.release()
        raise
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("SSH DNS deadline exceeded")
    try:
        ok, value = result.get(timeout=remaining)
    except queue.Empty:
        raise TimeoutError("SSH DNS deadline exceeded") from None
    if not ok:
        if isinstance(value, Exception):
            raise value
        raise OSError("SSH DNS lookup failed") from None
    return value


def _open_connection(address, timeout):
    """Use one deadline for DNS and every candidate TCP address."""
    deadline = time.monotonic() + timeout
    addresses = _resolve_addresses(*address, deadline)
    last_error = None
    for family, kind, protocol, _, sockaddr in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SSH TCP deadline exceeded")
        sock = None
        try:
            sock = socket.socket(family, kind, protocol)
            sock.settimeout(remaining)
            sock.connect(sockaddr)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("SSH TCP deadline exceeded")
            sock.settimeout(remaining)
            return sock
        except OSError as error:
            _close_quietly(sock)
            last_error = error
        except BaseException:
            _close_quietly(sock)
            raise
    if time.monotonic() >= deadline:
        raise TimeoutError("SSH TCP deadline exceeded")
    if last_error is not None:
        raise last_error
    raise OSError("SSH address lookup returned no usable address")


def _connect(options: SSHOptions):
    sock = transport = None
    try:
        sock = _open_connection((options.host, options.port), options.connect_timeout)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = options.connect_timeout
        transport.handshake_timeout = options.connect_timeout
        transport.auth_timeout = options.connect_timeout
        transport.channel_timeout = options.connect_timeout
        transport.start_client(timeout=options.connect_timeout)
        return transport, sock
    except Exception:
        _close_quietly(transport)
        _close_quietly(sock)
        raise


def fetch_host_key(options: SSHOptions) -> SSHHostKey:
    """Negotiate SSH and obtain a displayable host key without authenticating."""
    _validate_options(options)
    transport = sock = None
    try:
        transport, sock = _connect(options)
        return _identity(transport.get_remote_server_key())
    except SSHSetupError:
        raise
    except (socket.timeout, TimeoutError):
        raise SSHSetupError("timeout", "connect") from None
    except Exception:
        raise SSHSetupError("connection", "connect") from None
    finally:
        _close_quietly(transport)
        _close_quietly(sock)


def _unpack_payload(payload: bytes):
    if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_PAYLOAD:
        raise SSHSetupError("payload", "upload")
    files, total = {}, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            for index, member in enumerate(archive):
                if index >= len(_PAYLOAD_FILES) + 1:
                    raise ValueError
                if member.isdir() and member.name.rstrip("/") == "proxy":
                    continue
                if not member.isfile() or member.name not in _PAYLOAD_FILES or member.name in files:
                    raise ValueError
                total += member.size
                if member.size < 0 or total > _MAX_PAYLOAD:
                    raise ValueError
                with archive.extractfile(member) as source:
                    data = source.read(member.size + 1)
                if len(data) != member.size:
                    raise ValueError
                files[member.name] = data
        if set(files) != _PAYLOAD_FILES:
            raise ValueError
        return files
    except Exception:
        raise SSHSetupError("payload", "upload") from None


def _run_command(transport, command: str, *, timeout: float, stage: str,
                 capture=False):
    """Drain both SSH streams before reading status; return only bounded output."""
    channel = None
    output, count = bytearray(), 0
    deadline = time.monotonic() + timeout
    try:
        channel = transport.open_session(timeout=min(timeout, 15))
        channel.settimeout(min(timeout, 15))
        channel.exec_command(command)
        while True:
            if time.monotonic() >= deadline:
                raise SSHSetupError("timeout", stage)
            received = False
            for ready, receive, stdout in (
                (channel.recv_ready, channel.recv, True),
                (channel.recv_stderr_ready, channel.recv_stderr, False),
            ):
                while ready():
                    if time.monotonic() >= deadline:
                        raise SSHSetupError("timeout", stage)
                    chunk = receive(32768)
                    if not chunk:
                        break
                    received = True
                    count += len(chunk)
                    if count > _MAX_OUTPUT:
                        raise SSHSetupError("output_limit", stage)
                    if capture and stdout:
                        output.extend(chunk)
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                return channel.recv_exit_status(), bytes(output)
            if not received:
                time.sleep(0.01)
    finally:
        _close_quietly(channel)


def _open_sftp(transport, timeout):
    channel = transport.open_session(timeout=timeout)
    try:
        channel.settimeout(timeout)
        channel.invoke_subsystem("sftp")
        return paramiko.SFTPClient(channel)
    except Exception:
        _close_quietly(channel)
        raise


def _upload(sftp, stage, files, timeout):
    deadline = time.monotonic() + timeout
    sftp.mkdir(stage + "/proxy", mode=0o700)
    sftp.chmod(stage + "/proxy", 0o700)
    for name, contents in sorted(files.items()):
        if time.monotonic() >= deadline:
            raise SSHSetupError("timeout", "upload")
        sftp.get_channel().settimeout(max(0.1, min(15, deadline - time.monotonic())))
        path = stage + "/" + name
        with sftp.open(path, "wx", bufsize=0) as destination:
            sftp.chmod(path, 0o600)
            for offset in range(0, len(contents), 32768):
                if time.monotonic() >= deadline:
                    raise SSHSetupError("timeout", "upload")
                destination.write(contents[offset:offset + 32768])


def _read_result(sftp, path: str, host: str, *, registry_mode=False) -> DeploymentResult:
    metadata = sftp.lstat(path)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
            or metadata.st_uid != 0 or metadata.st_size > _MAX_RESULT):
        raise SSHSetupError("result", "verify_result")
    try:
        with sftp.open(path, "rb") as source:
            encoded = source.read(_MAX_RESULT + 1)
        if len(encoded) > _MAX_RESULT:
            raise ValueError
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        data = json.loads(encoded.decode("utf-8"), object_pairs_hook=pairs)
        expected = {"host", "port", "fingerprint", "registry", "helper_id"} if registry_mode else {"host", "port", "fingerprint", "token"}
        if not isinstance(data, dict) or set(data) != expected:
            raise ValueError()
        port, fingerprint = data["port"], data["fingerprint"]
        if (type(port) is not int or port != 8444 or not isinstance(fingerprint, str)
                or not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint)):
            raise ValueError
        if registry_mode:
            from proxy.registry_protocol import b64decode
            if data["registry"] is not True or data["host"] != str(ipaddress.ip_address(host)):
                raise ValueError()
            b64decode(data["helper_id"], 16)
            return DeploymentResult(host, port, fingerprint.lower(), registry=True, helper_id=data["helper_id"])
        token = data["token"]
        if (not isinstance(token, str) or not 32 <= len(token.encode("utf-8")) <= 512 or token != token.strip()
                or any(ord(character) < 32 or ord(character) == 127 for character in token)):
            raise ValueError()
        # The SSH address is user supplied and reachable. A server's first
        # local interface in result.host may be an unreachable private NAT IP.
        return DeploymentResult(host, port, fingerprint.lower(), token)
    except SSHSetupError:
        raise
    except Exception:
        raise SSHSetupError("result", "verify_result") from None


def _verify_endpoint(options: SSHOptions, result: DeploymentResult) -> None:
    """Confirm the public TLS endpoint against the SSH-delivered certificate.

    No helper token is sent during this check. Self-signed certificates are
    expected, and their complete DER SHA-256 fingerprint is mandatory.
    """
    raw = secured = None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = _open_connection((options.host, result.port), options.connect_timeout)
        secured = context.wrap_socket(raw, server_hostname=options.host)
        certificate = secured.getpeercert(binary_form=True)
        if (not certificate or not hmac.compare_digest(
                hashlib.sha256(certificate).hexdigest(), result.tls_fingerprint)):
            raise SSHSetupError("endpoint", "verify_result")
    except SSHSetupError:
        raise
    except Exception:
        raise SSHSetupError("endpoint", "verify_result") from None
    finally:
        _close_quietly(secured)
        _close_quietly(raw)


def _cleanup(sftp, stage):
    deadline = time.monotonic() + 5
    for name in ("result.json", *sorted(_PAYLOAD_FILES)):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        try:
            sftp.get_channel().settimeout(remaining)
            sftp.remove(stage + "/" + name)
        except OSError:
            pass
    for directory in (stage + "/proxy", stage):
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            sftp.get_channel().settimeout(remaining)
            sftp.rmdir(directory)
        except OSError:
            pass


def deploy_helper(options: SSHOptions, expected_host_key: SSHHostKey, payload: bytes,
                  progress: Optional[Callable[[str], None]] = None, *, registry_options: Optional[dict] = None) -> DeploymentResult:
    """Install only after the confirmed host key matches, before sending a password."""
    _validate_options(options, authenticate=True)
    registry_arguments = ""
    if registry_options is not None:
        try:
            from proxy.registry_protocol import decode_public_key
            if (not isinstance(registry_options, dict) or not {"url", "public_key"} <= set(registry_options)
                    or set(registry_options) - {"url", "public_key", "allow_existing_private_upgrade"}
                    or type(registry_options.get("allow_existing_private_upgrade", False)) is not bool):
                raise ValueError()
            address = ipaddress.ip_address(options.host)
            if (not address.is_global or address.is_multicast or address.is_unspecified or address.is_loopback
                    or address.is_link_local or getattr(address, "ipv4_mapped", None) is not None):
                raise ValueError()
            url = registry_options["url"]
            parsed = urllib.parse.urlsplit(url)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                    or parsed.query or parsed.fragment or len(url) > 512):
                raise ValueError()
            parsed.port
            decode_public_key(registry_options["public_key"])
            registry_arguments = (" --registry-mode --registry-url " + shlex.quote(url)
                + " --registry-trust-spki " + shlex.quote(registry_options["public_key"])
                + " --public-ip " + shlex.quote(str(address)))
            if registry_options.get("allow_existing_private_upgrade", False):
                registry_arguments += " --allow-existing-private-upgrade"
        except (ValueError, TypeError, KeyError):
            raise SSHSetupError("registry_options", "connect") from None
    files = _unpack_payload(payload)
    if (not isinstance(expected_host_key, SSHHostKey)
            or not isinstance(expected_host_key.key_data, bytes)
            or not expected_host_key.key_data
            or _fingerprint(expected_host_key.key_data) != expected_host_key.fingerprint):
        raise SSHSetupError("host_key_mismatch", "connect")
    transport = sock = sftp = None
    stage = "/root/.tg-proxy-setup-" + secrets.token_hex(12)
    stage_created = False
    current = "connect"

    def report(value):
        nonlocal current
        current = value
        if progress is not None:
            progress(value)

    try:
        report("connect")
        transport, sock = _connect(options)
        actual = _identity(transport.get_remote_server_key())
        if (actual.key_type != expected_host_key.key_type
                or not hmac.compare_digest(actual.key_data, expected_host_key.key_data)):
            raise SSHSetupError("host_key_mismatch", current)
        transport.auth_password(options.username, options.password, fallback=False)
        if not transport.is_authenticated():
            raise SSHSetupError("authentication", current)
        report("verify")
        status, output = _run_command(transport, "id -u", timeout=options.connect_timeout,
                                      stage=current, capture=True)
        if status != 0 or output.strip() != b"0":
            raise SSHSetupError("root_required", current)
        status, _ = _run_command(transport, _SUPPORTED_SYSTEM, timeout=options.connect_timeout, stage=current)
        if status != 0:
            raise SSHSetupError("unsupported_system", current)
        report("upload")
        sftp = _open_sftp(transport, options.connect_timeout)
        sftp.mkdir(stage, mode=0o700)
        stage_created = True
        sftp.chmod(stage, 0o700)
        _upload(sftp, stage, files, timeout=min(90, options.command_timeout))
        report("install")
        command = (
            f"timeout --signal=TERM --kill-after=45s {max(1, int(options.command_timeout))}s "
            f"bash {shlex.quote(stage + '/deploy_helper.sh')} "
            f"--result-file {shlex.quote(stage + '/result.json')}" + registry_arguments
        )
        status, _ = _run_command(transport, command, timeout=options.command_timeout + 60, stage=current)
        if status != 0:
            raise SSHSetupError("timeout" if status in (124, 137) else "install", current)
        report("verify_result")
        status, _ = _run_command(transport, "systemctl is-active --quiet tg-helper.service",
                                 timeout=options.connect_timeout, stage=current)
        if status != 0:
            raise SSHSetupError("install", current)
        sftp.get_channel().settimeout(options.connect_timeout)
        result = _read_result(sftp, stage + "/result.json", options.host, registry_mode=registry_options is not None)
        _verify_endpoint(options, result)
        return result
    except SSHSetupError:
        raise
    except paramiko.AuthenticationException:
        raise SSHSetupError("authentication", current) from None
    except (socket.timeout, TimeoutError):
        raise SSHSetupError("timeout", current) from None
    except Exception:
        raise SSHSetupError("connection" if current == "connect" else current, current) from None
    finally:
        if sftp is not None:
            if stage_created:
                try:
                    _cleanup(sftp, stage)
                except Exception:
                    pass
            _close_quietly(sftp)
        _close_quietly(transport)
        _close_quietly(sock)
