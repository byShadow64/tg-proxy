"""Publish one signed Android dev bundle without rebuilding or changing Windows metadata."""
from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import re
import secrets
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request

_SPEC = importlib.util.spec_from_file_location("tgproxy_android_prepare", Path(__file__).with_name("prepare-update.py"))
prepare = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(prepare)
UpdateError, require = prepare.UpdateError, prepare.require
REMOTE = "/updates"
WINDOWS_METADATA = ("/updates/latest.json", "/updates/candidate/latest.json")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UpdateError("https_redirect")


def response_length(headers, maximum, expected_size=None):
    # Mirror the Android raw HTTP parser rather than accepting urllib-only framing.
    items = list(headers.items())
    names = [name.lower() for name, _ in items]
    require(len(items) <= 32 and len(names) == len(set(names)), "https_headers")
    require(all(re.fullmatch("[a-z0-9-]+", name) for name in names), "https_headers")
    require(all(all(32 <= ord(c) <= 126 or c == "\t" for c in value) for _, value in items), "https_headers")
    require(sum(len(name) + len(value) + 4 for name, value in items) + 32 <= 8192, "https_headers")
    normalized = {name.lower(): value.strip() for name, value in items}
    require("transfer-encoding" not in normalized, "https_encoding")
    require(normalized.get("content-encoding", "identity").lower() == "identity", "https_encoding")
    lengths = headers.get_all("Content-Length") or []
    require(len(lengths) == 1, "https_size")
    text = lengths[0].strip()
    require(re.fullmatch("[0-9]{1,10}", text) is not None, "https_size")
    length = int(text)
    require(1 <= length <= maximum and (expected_size is None or length == expected_size), "https_size")
    return length


def https_bytes(path, maximum, *, expected_size=None, allow_missing=False):
    require(path.startswith("/android-dev/") and "//" not in path and ".." not in path.split("/"), "https_path")
    url = prepare.ORIGIN + path
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    deadline = time.monotonic() + 180
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache",
                                                  "User-Agent": "TGProxyAndroidPublisher/1"})
    try:
        with opener.open(request, timeout=15) as response:
            require(response.status == 200 and response.url == url, "https_status")
            length = response_length(response.headers, maximum, expected_size)
            data = bytearray()
            while True:
                require(time.monotonic() < deadline, "https_timeout")
                chunk = response.read(min(65536, maximum + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                require(len(data) <= maximum, "https_size")
            require(len(data) == length, "https_size")
            return bytes(data)
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        if allow_missing and code == 404:
            return None
        raise UpdateError("https_status") from None
    except UpdateError:
        raise
    except Exception:
        raise UpdateError("https_verification") from None


class Connection:
    """Current exact host key is checked before any SSH credential is transmitted."""
    def __init__(self):
        self.sftp = self.transport = self.sock = None

    def __enter__(self):
        from publisher.profiles import ServerCredentials, load_default_profile, validate_profile
        from publisher.server import _auth
        from utils import ssh_setup
        profile = validate_profile(load_default_profile())
        require(profile.base_url.rstrip("/") == prepare.ORIGIN and profile.webroot == REMOTE, "profile_origin")
        require(bool(profile.host_key_data), "host_key")
        options, key = _auth(profile, ServerCredentials())
        try:
            self.transport, self.sock = ssh_setup._connect(options)
            actual = self.transport.get_remote_server_key()
            expected = base64.b64decode(profile.host_key_data, validate=True)
            require(actual.get_name() == profile.host_key_type
                    and hmac.compare_digest(actual.asbytes(), expected), "host_key")
            if key is not None:
                self.transport.auth_publickey(options.username, key)
            else:
                self.transport.auth_password(options.username, options.password, fallback=False)
            require(self.transport.is_authenticated(), "ssh_auth")
            self.transport.set_keepalive(20)
            self.sftp = ssh_setup._open_sftp(self.transport, 15)
            self.sftp.get_channel().settimeout(15)
            return self.sftp
        except UpdateError:
            self.__exit__(None, None, None)
            raise
        except Exception:
            self.__exit__(None, None, None)
            raise UpdateError("ssh_connection") from None

    def __exit__(self, *_):
        from utils import ssh_setup
        for resource in (self.sftp, self.transport, self.sock):
            ssh_setup._close_quietly(resource)


def remote_stat(sftp, path):
    try:
        return sftp.lstat(path)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return None
        raise UpdateError("remote_stat") from None


def require_directory(sftp, path, *, create=False):
    meta = remote_stat(sftp, path)
    if meta is None and create:
        sftp.mkdir(path, mode=0o755)
        meta = sftp.lstat(path)
    require(meta is not None and stat.S_ISDIR(meta.st_mode) and sftp.normalize(path) == path, "remote_directory")


def remote_read(sftp, path, maximum, *, optional=False):
    meta = remote_stat(sftp, path)
    if meta is None:
        require(optional, "remote_missing")
        return None
    require(stat.S_ISREG(meta.st_mode) and 0 <= meta.st_size <= maximum
            and sftp.normalize(path) == path, "remote_file")
    deadline = time.monotonic() + 180
    result = bytearray()
    try:
        with sftp.open(path, "rb") as source:
            while True:
                require(time.monotonic() < deadline, "download_timeout")
                sftp.get_channel().settimeout(max(0.1, min(15, deadline - time.monotonic())))
                chunk = source.read(min(65536, maximum + 1 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
                require(len(result) <= maximum, "remote_size")
    finally:
        sftp.get_channel().settimeout(15)
    require(len(result) == meta.st_size, "remote_size")
    return bytes(result)


def remote_write_new(sftp, path, data):
    deadline = time.monotonic() + 180
    with sftp.open(path, "wx", bufsize=0) as target:
        sftp.chmod(path, 0o644)
        for offset in range(0, len(data), 32768):
            require(time.monotonic() < deadline, "upload_timeout")
            sftp.get_channel().settimeout(max(0.1, min(15, deadline - time.monotonic())))
            target.write(data[offset:offset + 32768])
        target.flush()
    sftp.get_channel().settimeout(15)


def compatible_existing(encoded, new, *, monotonic, verify=prepare.verify_manifest):
    if encoded is None:
        return
    old = verify(encoded)
    if monotonic:
        require(old["version_code"] <= new["version_code"], "downgrade")
    if old["version_code"] == new["version_code"]:
        require(old["sha256"] == new["sha256"] and old["size"] == new["size"], "version_conflict")
        require(old == new, "metadata_conflict")


def publish_sftp(sftp, payload, encoded, apk, candidate=False, *,
                 verify_manifest=prepare.verify_manifest, fetch=https_bytes):
    """No SSH commands; serialize this publisher and commit metadata by atomic rename."""
    require_directory(sftp, REMOTE)
    require_directory(sftp, REMOTE + "/android-dev", create=True)
    lock = REMOTE + "/android-dev/.publisher-lock"
    acquired = False
    temporary = []
    committed = False
    channel_path = "/android-dev/candidate/latest.json" if candidate else "/android-dev/latest.json"
    target = REMOTE + channel_path
    before_windows = {path: remote_read(sftp, path, 1024 * 1024) for path in WINDOWS_METADATA}
    try:
        try:
            sftp.mkdir(lock, mode=0o700)
            acquired = True
        except OSError:
            raise UpdateError("publication_busy") from None
        require_directory(sftp, lock)
        require_directory(sftp, REMOTE + "/android-dev/releases", create=True)
        release_dir = REMOTE + "/android-dev/releases/" + str(payload["version_code"])
        require_directory(sftp, release_dir, create=True)
        if candidate:
            require_directory(sftp, REMOTE + "/android-dev/candidate", create=True)
        channels = [REMOTE + "/android-dev/latest.json", REMOTE + "/android-dev/candidate/latest.json"]
        # A missing candidate directory is legitimate on first dev-channel publication.
        existing = {}
        for path in channels:
            parent = path.rsplit("/", 1)[0]
            if remote_stat(sftp, parent) is None:
                existing[path] = None
            else:
                require_directory(sftp, parent)
                existing[path] = remote_read(sftp, path, prepare.MAX_METADATA, optional=True)
            compatible_existing(existing[path], payload, monotonic=path == target, verify=verify_manifest)
        filename = payload["sha256"] + ".apk"
        # A version code cannot silently acquire another APK after either channel used it.
        require(set(sftp.listdir(release_dir)) <= {filename}, "release_directory_conflict")
        destination = REMOTE + payload["apk_path"]
        remote = remote_read(sftp, destination, prepare.MAX_APK, optional=True)
        reused = remote is not None
        if remote is not None:
            require(len(remote) == payload["size"] and hashlib.sha256(remote).hexdigest() == payload["sha256"], "immutable_apk_conflict")
        else:
            staged = release_dir + "/.upload-" + secrets.token_hex(12) + ".tmp"
            temporary.append(staged)
            remote_write_new(sftp, staged, apk)
            uploaded = remote_read(sftp, staged, prepare.MAX_APK)
            require(len(uploaded) == payload["size"] and hashlib.sha256(uploaded).hexdigest() == payload["sha256"], "upload_hash")
            # Standard SFTP rename must fail if destination exists; never use replacement here.
            sftp.rename(staged, destination)
            temporary.remove(staged)
        public_apk = fetch(payload["apk_path"], prepare.MAX_APK, expected_size=payload["size"])
        require(hashlib.sha256(public_apk).hexdigest() == payload["sha256"], "https_apk_hash")
        for path, previous in existing.items():
            parent = path.rsplit("/", 1)[0]
            current = None if remote_stat(sftp, parent) is None else remote_read(sftp, path, prepare.MAX_METADATA, optional=True)
            require(current == previous, "concurrent_metadata_change")
        require(all(remote_read(sftp, path, 1024 * 1024) == data for path, data in before_windows.items()), "windows_metadata_changed")
        if existing[target] != encoded:
            staged_meta = target.rsplit("/", 1)[0] + "/.latest-" + secrets.token_hex(12) + ".tmp"
            temporary.append(staged_meta)
            remote_write_new(sftp, staged_meta, encoded)
            require(remote_read(sftp, staged_meta, prepare.MAX_METADATA) == encoded, "metadata_upload")
            # Requires OpenSSH atomic replacement extension; no remove/rename fallback.
            sftp.posix_rename(staged_meta, target)
            temporary.remove(staged_meta)
            committed = True
        public_meta = fetch(channel_path, prepare.MAX_METADATA, expected_size=len(encoded))
        require(public_meta == encoded, "https_metadata")
        require(verify_manifest(public_meta) == payload, "https_metadata")
        require(all(remote_read(sftp, path, 1024 * 1024) == data for path, data in before_windows.items()), "windows_metadata_changed")
        return {"status": "published_and_verified", "channel": "candidate" if candidate else "dev",
                "version": payload["version_name"], "version_code": payload["version_code"],
                "sha256": payload["sha256"], "size": payload["size"], "reused_apk": reused,
                "manifest_url": prepare.ORIGIN + channel_path, "apk_url": prepare.ORIGIN + payload["apk_path"],
                "windows_metadata_unchanged": True, "github_changed": False}
    except KeyboardInterrupt:
        raise UpdateError("cancelled", committed=committed) from None
    except UpdateError as error:
        raise UpdateError(error.code, committed=committed or error.committed) from None
    except Exception:
        raise UpdateError("publication_failed", committed=committed) from None
    finally:
        for path in temporary:
            try:
                sftp.remove(path)
            except OSError:
                pass
        if acquired:
            try:
                sftp.rmdir(lock)
            except OSError:
                pass


def publish(args):
    payload, encoded, apk = prepare.load_bundle(args.bundle)
    # Check platform TLS before opening an SSH mutation session. A fresh channel is404.
    path = "/android-dev/candidate/latest.json" if args.candidate else "/android-dev/latest.json"
    previous = https_bytes(path, prepare.MAX_METADATA, allow_missing=True)
    compatible_existing(previous, payload, monotonic=True)
    with Connection() as sftp:
        return publish_sftp(sftp, payload, encoded, apk, candidate=args.candidate)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--candidate", action="store_true", help="Verify private candidate channel before promoting the same bundle")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(publish(args), ensure_ascii=False))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"error": "cancelled"}), file=sys.stderr)
        return 130
    except Exception as error:
        code = getattr(error, "code", "publication_failed")
        code = code if isinstance(code, str) and re.fullmatch("[a-z_]{1,64}", code) else "publication_failed"
        print(json.dumps({"error": code, "committed": bool(getattr(error, "committed", False))}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
