"""Publish the same approved bundle to a selected HTTPS/SFTP server."""
from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import hmac
import io
import json
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import paramiko

from publisher.bundle import ReleaseBundle, revalidate_bundle
from publisher.legacy import publication_core
from publisher.profiles import ServerCredentials, ServerProfile, default_keys_path, validate_profile
from utils import ssh_setup
from utils.secure_storage import unprotect_token


class ServerError(RuntimeError):
    def __init__(self, code: str, *, committed=False):
        self.code, self.committed = code, committed
        super().__init__("Server publication failed (" + code + ")")


def _emit(emit, phase, **values):
    if emit is not None:
        try:
            emit(dict(phase=phase, **values))
        except Exception:
            pass


def _cancelled(cancel):
    if cancel is None:
        return False
    try:
        return bool(cancel.is_set() if hasattr(cancel, "is_set") else cancel())
    except Exception:
        return True


def _check_cancel(cancel):
    if _cancelled(cancel):
        raise ServerError("cancelled")


def _key_file(path):
    value = Path(path).expanduser()
    project = Path(__file__).resolve().parents[1]
    if (value.is_symlink() or not value.is_file() or value.stat().st_size > 128 * 1024
            or value.resolve().is_relative_to(project)):
        raise ServerError("credentials")
    return value


def _legacy_keys(credentials):
    try:
        path = _key_file(credentials.legacy_key_path or default_keys_path())
        saved = json.loads(path.read_text(encoding="utf-8"))
        from proxy.update_channel import TRUSTED_UPDATE_KEYS
        if TRUSTED_UPDATE_KEYS.get(saved["key_id"]) != saved["public_key"]:
            raise ValueError
        return saved
    except ServerError:
        raise
    except Exception:
        raise ServerError("signing_key") from None


def load_signing_key(credentials: ServerCredentials):
    """Return (in-memory private key, key_id); never serialize or export it."""
    try:
        saved = _legacy_keys(credentials)
        secret = base64.b64decode(unprotect_token(saved["signing_key_dpapi"]), validate=True)
        key = Ed25519PrivateKey.from_private_bytes(secret)
        from cryptography.hazmat.primitives import serialization
        public = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        if not hmac.compare_digest(public, saved["public_key"]):
            raise ValueError
        return key, saved["key_id"]
    except Exception:
        raise ServerError("signing_key") from None


def signing_identity(credentials=None):
    return load_signing_key(credentials or ServerCredentials())


def approve_local_bundle(bundle, credentials=None):
    """Explicit UI approval action; callers must require completed-test consent.

    The signed sidecar lives in app data, never inside the immutable package.
    """
    import os
    import secrets
    from publisher.bundle import BundleError, canonical_json
    from publisher.trust import TrustError, approve_bundle, approval_file
    temporary = None
    try:
        bundle = revalidate_bundle(bundle)
        key, key_id = signing_identity(credentials)
        approval = approve_bundle(bundle, key, key_id)
        path = approval_file(bundle.bundle_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise ServerError("approval_file")
        temporary = path.with_name(".approval." + secrets.token_hex(12) + ".tmp")
        with temporary.open("xb") as target:
            target.write(canonical_json(approval) + b"\n")
        os.replace(temporary, path)
        return approval
    except (ServerError, BundleError, TrustError):
        raise
    except Exception:
        raise ServerError("approval_file") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _auth(profile, credentials):
    if not isinstance(credentials, ServerCredentials):
        raise ServerError("credentials")
    key = None
    try:
        if profile.auth_method == "legacy":
            saved = _legacy_keys(credentials)
            key = paramiko.Ed25519Key.from_private_key(io.StringIO(unprotect_token(saved["ssh_key_dpapi"])))
        elif profile.auth_method == "key":
            path = _key_file(credentials.private_key_path)
            data = path.read_text(encoding="utf-8")
            for kind in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
                try:
                    key = kind.from_private_key(io.StringIO(data), password=credentials.key_passphrase or None)
                    break
                except (paramiko.SSHException, ValueError):
                    continue
            if key is None:
                raise ValueError
        elif profile.auth_method != "password" or not credentials.password:
            raise ValueError
        return ssh_setup.SSHOptions(profile.host, username=profile.username, port=profile.port,
                                    password=credentials.password if profile.auth_method == "password" else ""), key
    except Exception:
        raise ServerError("credentials") from None


def _expected_key(profile):
    if profile.host_key_data:
        data = base64.b64decode(profile.host_key_data, validate=True)
        return ssh_setup.SSHHostKey(profile.host_key_type, data, profile.host_key)
    return profile.host_key


def _check_https(profile, cancel=None):
    from utils.update_check import _open_response, _response_url
    _check_cancel(cancel)
    request = urllib.request.Request(profile.base_url.rstrip("/") + "/latest.json", method="HEAD")
    try:
        with _open_response(request, timeout=15, response_timeout=20) as response:
            _response_url(response, request.full_url)
            if response.status not in (200, 204):
                raise ServerError("https")
    except urllib.error.HTTPError as error:
        # A fresh server has no manifest yet; its HTTPS identity is still verified.
        status = error.code
        error.close()
        if status != 404:
            raise ServerError("https") from None
    except ServerError:
        raise
    except Exception:
        raise ServerError("https") from None
    _check_cancel(cancel)


def probe_host_key(profile: ServerProfile):
    validate_profile(profile, require_pin=False)
    try:
        return ssh_setup.fetch_host_key(ssh_setup.SSHOptions(profile.host, username=profile.username, port=profile.port))
    except Exception:
        raise ServerError("connection") from None


def check_server(profile: ServerProfile, credentials: ServerCredentials, emit=None, cancel=None):
    validate_profile(profile)
    _emit(emit, "checking_https")
    _check_https(profile, cancel)
    options, key = _auth(profile, credentials)
    transport = sock = sftp = None
    try:
        _check_cancel(cancel)
        _emit(emit, "connecting")
        transport, sock = ssh_setup._connect(options)
        actual = ssh_setup._identity(transport.get_remote_server_key())
        if (not hmac.compare_digest(actual.fingerprint, profile.host_key)
                or (profile.host_key_data and
                    (actual.key_type != profile.host_key_type or not hmac.compare_digest(
                        actual.key_data, base64.b64decode(profile.host_key_data, validate=True))))):
            raise ServerError("host_key_mismatch")
        _check_cancel(cancel)
        if key is not None:
            transport.auth_publickey(options.username, key)
        else:
            transport.auth_password(options.username, options.password, fallback=False)
        if not transport.is_authenticated():
            raise ServerError("authentication")
        sftp = ssh_setup._open_sftp(transport, options.connect_timeout)
        _check_cancel(cancel)
        publication_core()._require_directory(sftp, profile.webroot)
        sftp.listdir(profile.webroot)
        _check_cancel(cancel)
        return {"status": "ready", "https_verified": True, "sftp_verified": True,
                "webroot_exists": True, "write_verified": False}
    except ServerError:
        raise
    except Exception:
        raise ServerError("sftp") from None
    finally:
        for resource in (sftp, transport, sock):
            ssh_setup._close_quietly(resource)


def _verify_public(bundle, profile, emit, cancel, *, release=None):
    from utils.update_check import fetch_backup_release, _open_response, _response_url, _read_chunk
    _emit(emit, "verifying_public")
    _check_cancel(cancel)
    release = release or fetch_backup_release(profile.base_url.rstrip("/") + "/latest.json", timeout=20)
    if release["latest"] != bundle.version or len(release["assets"]) != len(bundle.assets):
        raise ServerError("public_verification", committed=True)
    for asset in release["assets"]:
        _check_cancel(cancel)
        name = asset["name"]
        if (name not in bundle.assets or asset["digest"] != "sha256:" + bundle.manifest["assets"][name]
                or asset["size"] != bundle.asset_sizes[name]):
            raise ServerError("public_verification", committed=True)
        digest, count = hashlib.sha256(), 0
        # Use production TLS/redirect/deadline primitives, but retain direct
        # cancellation between bounded reads rather than a swallowed callback.
        with _open_response(asset["url"], timeout=15, response_timeout=90) as response:
            _response_url(response, asset["url"])
            while True:
                _check_cancel(cancel)
                chunk = _read_chunk(response, 65536)
                if not chunk:
                    break
                count += len(chunk)
                if count > asset["size"]:
                    raise ServerError("public_verification", committed=True)
                digest.update(chunk)
                _emit(emit, "verifying_public", bytes=count, total=asset["size"])
        if count != asset["size"] or digest.hexdigest() != bundle.manifest["assets"][name]:
            raise ServerError("public_verification", committed=True)


def verify_publication(bundle, profile, emit=None, cancel=None):
    """Read-only verification; does not connect to SSH or re-sign a manifest."""
    from utils.update_check import fetch_backup_release
    bundle = revalidate_bundle(bundle)
    validate_profile(profile, require_pin=False)
    _check_cancel(cancel)
    url = profile.base_url.rstrip("/") + "/latest.json"
    try:
        release = fetch_backup_release(url, timeout=20)
        if release["latest"] != bundle.version:
            return {"status": "different_version", "version": bundle.version,
                    "current_version": release["latest"], "public_verified": False}
        _verify_public(bundle, profile, emit, cancel, release=release)
        return {"status": "published_and_verified", "version": bundle.version,
                "manifest_url": url, "public_verified": True}
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"status": "not_published", "version": bundle.version, "public_verified": False}
        raise ServerError("public_verification") from None
    except ServerError as error:
        raise ServerError(error.code) from None
    except Exception:
        raise ServerError("public_verification") from None


def publish_bundle(bundle: ReleaseBundle, profile: ServerProfile, credentials: ServerCredentials,
                   emit=None, cancel=None, *, approval=None):
    from publisher.trust import verify_approval
    _emit(emit, "validating")
    _check_cancel(cancel)
    bundle = revalidate_bundle(bundle)
    verify_approval(bundle, approval)
    validate_profile(profile)
    _emit(emit, "checking_https")
    _check_https(profile, cancel)
    key, key_id = load_signing_key(credentials)
    options, ssh_key = _auth(profile, credentials)
    core = publication_core()
    options = replace(options, command_timeout=core.transfer_timeout_for_size(sum(bundle.asset_sizes.values())))
    manifest = core.build_signed_manifest(bundle.version, bundle.assets, profile.base_url, key, key_id,
                                           notes=bundle.notes)
    # build_signed_manifest reads paths again. Refuse a newly substituted EXE,
    # checksum file or notes before the shared publisher can contact SSH. The
    # shared publisher then captures bytes and checks against this exact bound
    # manifest itself, closing the remaining filesystem substitution window.
    try:
        payload = core._parse_manifest(manifest, current=True)
        if (payload["version"] != bundle.version or payload["notes"] != bundle.notes
                or {entry["name"] for entry in payload["assets"]} != set(bundle.assets)
                or any(entry["sha256"] != bundle.manifest["assets"][entry["name"]]
                       or entry["size"] != bundle.asset_sizes[entry["name"]]
                       for entry in payload["assets"])):
            raise ValueError
    except Exception:
        raise ServerError("bundle_changed") from None
    _check_cancel(cancel)
    try:
        report = core.publish_release(options, _expected_key(profile), profile.webroot, bundle.assets,
                                      manifest, ssh_private_key=ssh_key, emit=emit, cancel=cancel)
    except core.PublicationError as error:
        raise ServerError(error.code) from None
    result = {"status": "published_and_verified", "version": report.version,
              "manifest_url": profile.base_url.rstrip("/") + "/latest.json",
              "uploaded_files": list(report.uploaded_files), "reused_version": report.reused_version,
              "public_verified": False}
    try:
        _verify_public(bundle, profile, emit, cancel)
    except Exception:
        if _cancelled(cancel):
            # Commit already happened. Never claim that cancellation undid it.
            result["status"] = "published_verification_pending"
            return result
        raise ServerError("public_verification", committed=True) from None
    result["public_verified"] = True
    _emit(emit, "complete")
    return result
