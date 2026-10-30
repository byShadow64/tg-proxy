"""Promote exact approved release bytes from a trusted GitHub Actions run.

No tag replacement, asset deletion, rebuilding, or project code execution is
performed. Tokens remain in memory and are never included in reported errors.
"""
from __future__ import annotations

import hashlib
from enum import Enum
import http.client
import json
import math
import os
import re
import socket
import ssl
import stat
import threading
import time
import tempfile
import zipfile
from functools import partial
from contextlib import suppress
from pathlib import Path
from urllib.parse import quote, urlencode, urljoin, urlsplit


ASSETS = frozenset({"TgWsProxy_windows.exe", "TgWsProxy_helper.zip", "SHA256SUMS.txt", "CHANGELOG.md"})
API_HOST = "api.github.com"
UPLOAD_HOST = "uploads.github.com"
API_VERSION = "2026-03-10"
MAX_JSON = 4 * 1024 * 1024
MAX_ASSET = 512 * 1024 * 1024
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")
_VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COOLDOWNS = {}
_COOLDOWN_LOCK = threading.Lock()
_HTTP_LOCK = threading.RLock()
_LAST_WRITE = 0.


class InputEndpoint(str, Enum):
    DRAFT_METADATA = "draft_metadata"
    ASSET_METADATA = "asset_metadata"
    ASSET_DOWNLOAD = "asset_download"


class GitHubError(RuntimeError):
    def __init__(self, code, http_status=None, retry_after=None):
        self.code = code
        self.http_status = http_status
        self.retry_after = retry_after
        super().__init__("GitHub publication: " + code)


def _check_cancel(cancel):
    if cancel is not None and (cancel.is_set() if hasattr(cancel, "is_set") else cancel()):
        raise GitHubError("cancelled")


def _emit(emit, phase, **values):
    if emit is not None:
        try:
            emit({"channel": "github", "phase": phase, **values})
        except Exception:
            pass


def _version(value):
    match = _VERSION.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise GitHubError("stable_version_required")
    return tuple(map(int, match.groups()))


def _positive_id(value):
    if type(value) is not int or value <= 0:
        raise GitHubError("invalid_response")
    return value


def _repository(value):
    if not isinstance(value, str) or _REPOSITORY.fullmatch(value) is None or value.endswith(("/.", "/..")):
        raise GitHubError("invalid_repository")
    return value


def _error_status(status):
    return {401: "authentication_required", 403: "permission_or_rate_limit", 404: "not_found", 409: "conflict", 422: "conflict", 429: "rate_limited"}.get(status, "http_error")


def _download_host(host):
    return host in {API_HOST, "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"} or bool(re.fullmatch(r"productionresults[a-z0-9]+\.blob\.core\.windows\.net", host or ""))


class GitHubClient:
    """Small bounded transport; redirects never carry the Authorization header."""

    def __init__(self, token, *, cancel=None, emit=None, _connection_factory=None, timeout=10.0):
        if not isinstance(token, str) or not token or len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise GitHubError("invalid_token")
        self._token = token
        self.cancel = cancel
        self.emit = emit
        self.timeout = min(max(float(timeout), .1), 20.)
        self._factory = _connection_factory or http.client.HTTPSConnection
        self.trusted_run_id = None
        self._last_mutation = 0.
        self._rate_key = hashlib.sha256(token.encode("ascii")).hexdigest()

    def _request(self, *args, **kwargs):
        with _HTTP_LOCK:
            upload = kwargs.get("upload")
            expected_hash = kwargs.pop("expected_sha256", None)
            if upload is None:
                return self._request_serial(*args, **kwargs)
            # Freeze and verify before even opening an HTTP connection. The
            # original file is never reopened after verification or streamed
            # directly to GitHub, including when a same-size file is replaced.
            expected_size = kwargs.get("expected_size")
            maximum = MAX_ASSET
            if type(expected_size) is not int or not 0 < expected_size <= maximum or not isinstance(expected_hash, str) or _DIGEST.fullmatch(expected_hash) is None:
                raise GitHubError("bundle_invalid")
            try:
                path = Path(upload)
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size != expected_size:
                    raise GitHubError("bundle_changed")
                with tempfile.TemporaryFile(mode="w+b") as snapshot:
                    count, digest = 0, hashlib.sha256()
                    with path.open("rb") as source:
                        while chunk := source.read(256 * 1024):
                            _check_cancel(self.cancel)
                            count += len(chunk)
                            if count > expected_size:
                                raise GitHubError("bundle_changed")
                            digest.update(chunk)
                            snapshot.write(chunk)
                    if count != expected_size or digest.hexdigest() != expected_hash:
                        raise GitHubError("bundle_changed")
                    snapshot.flush()
                    snapshot.seek(0)
                    kwargs.update(upload=snapshot, upload_name=path.name)
                    return self._request_serial(*args, **kwargs)
            except GitHubError:
                raise
            except OSError:
                raise GitHubError("bundle_changed") from None

    def _request_serial(self, method, url, *, data=None, upload=None, expected_size=None,
                 accept="application/vnd.github+json", authenticated=True,
                 max_bytes=MAX_JSON, redirects=False, sink=None, deadline_seconds=180, upload_name=None):
        global _LAST_WRITE
        deadline = time.monotonic() + deadline_seconds
        with _COOLDOWN_LOCK:
            until = _COOLDOWNS.get(self._rate_key, 0.)
        if until > time.monotonic():
            raise GitHubError("rate_limited", retry_after=max(1, math.ceil(until-time.monotonic())))
        if method in {"POST", "PATCH", "PUT", "DELETE"}:
            while time.monotonic() - _LAST_WRITE < 1.:
                _check_cancel(self.cancel)
                time.sleep(.05)
            self._last_mutation = time.monotonic()
            _LAST_WRITE = self._last_mutation
        for redirect_count in range(5):
            _check_cancel(self.cancel)
            parsed = urlsplit(url)
            try:
                valid_port = parsed.port in (None, 443)
            except ValueError:
                raise GitHubError("unsafe_url") from None
            if parsed.scheme != "https" or not valid_port or parsed.username or parsed.password or parsed.fragment:
                raise GitHubError("unsafe_url")
            host = parsed.hostname
            if authenticated and host not in {API_HOST, UPLOAD_HOST}:
                raise GitHubError("unsafe_url")
            if not authenticated and not _download_host(host):
                raise GitHubError("unsafe_redirect")
            connection = response = None
            try:
                connection = self._factory(host, timeout=min(self.timeout, max(.1, deadline-time.monotonic())), context=ssl.create_default_context())
                # A socket inactivity timeout cannot bound DNS, slow status
                # lines or HTTP chunk framing. Keep the same absolute deadline
                # for connection setup and the response, including redirects.
                from proxy.http_transport import create_connection
                from proxy.http_transport import response_with_deadline
                connection._create_connection = partial(create_connection, deadline=deadline)
                connection.response_class = response_with_deadline(deadline)
                headers = {"Accept": accept, "User-Agent": "TGProxy-Publisher/1", "X-GitHub-Api-Version": API_VERSION}
                if authenticated:
                    headers["Authorization"] = "Bearer " + self._token
                if upload is not None:
                    headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(expected_size)})
                    connection.putrequest(method, parsed.path + ("?" + parsed.query if parsed.query else ""))
                    for name, value in headers.items():
                        connection.putheader(name, value)
                    connection.endheaders()
                    count = 0
                    for chunk in iter(lambda: upload.read(64 * 1024), b""):
                        _check_cancel(self.cancel)
                        if time.monotonic() >= deadline:
                            raise GitHubError("timeout")
                        count += len(chunk)
                        if count > expected_size:
                            raise GitHubError("bundle_changed")
                        connection.send(chunk)
                        _emit(self.emit, "uploading", bytes=count, total=expected_size, asset=upload_name)
                    if count != expected_size:
                        raise GitHubError("bundle_changed")
                else:
                    if data is not None:
                        headers["Content-Type"] = "application/json"
                    connection.request(method, parsed.path + ("?" + parsed.query if parsed.query else ""), body=data, headers=headers)
                response = connection.getresponse()
                if response.status in {301, 302, 303, 307, 308}:
                    if not redirects or method != "GET" or redirect_count >= 3:
                        raise GitHubError("unsafe_redirect")
                    location = response.getheader("Location")
                    if not isinstance(location, str) or len(location) > 16384:
                        raise GitHubError("unsafe_redirect")
                    url = urljoin(url, location)
                    authenticated = False
                    continue
                if response.status < 200 or response.status >= 300:
                    secondary = False
                    if response.status == 403:
                        try:
                            parts, received = [], 0
                            while received < 4096:
                                _check_cancel(self.cancel)
                                if time.monotonic() >= deadline:
                                    break
                                part = response.read1(4096 - received)
                                if not part:
                                    break
                                parts.append(part)
                                received += len(part)
                            # Classify only a fixed allowlisted reason. The body
                            # is discarded and never returned, logged, or raised.
                            message = b"".join(parts).decode("utf-8", "replace").lower()
                            secondary = "secondary rate limit" in message or "abuse detection" in message
                        except (ValueError, OSError, http.client.HTTPException):
                            pass
                    rate = secondary or response.status == 429 or response.getheader("X-RateLimit-Remaining") == "0" or response.getheader("Retry-After") is not None
                    retry = None
                    if rate:
                        try:
                            retry_after = response.getheader("Retry-After")
                            reset = response.getheader("X-RateLimit-Reset")
                            if retry_after is not None:
                                retry = max(1, min(86400, int(retry_after)))
                            elif response.getheader("X-RateLimit-Remaining") == "0" and reset is not None:
                                retry = max(1, min(86400, math.ceil(float(reset) - time.time())))
                            else:
                                retry = 60
                        except (ValueError, OverflowError):
                            retry = 60
                        with _COOLDOWN_LOCK:
                            _COOLDOWNS[self._rate_key] = time.monotonic() + retry
                    raise GitHubError("rate_limited" if rate else _error_status(response.status), response.status, retry)
                length = response.getheader("Content-Length")
                if length is not None:
                    try:
                        if int(length) < 0 or int(length) > max_bytes:
                            raise GitHubError("response_too_large")
                    except ValueError:
                        raise GitHubError("invalid_response") from None
                chunks, count = [], 0
                while True:
                    _check_cancel(self.cancel)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise GitHubError("timeout")
                    if connection.sock is not None:
                        connection.sock.settimeout(min(self.timeout, remaining))
                    chunk = response.read1(min(64 * 1024, max_bytes - count + 1))
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > max_bytes:
                        raise GitHubError("response_too_large")
                    if sink:
                        sink(chunk)
                    else:
                        chunks.append(chunk)
                return b"".join(chunks), count
            except GitHubError:
                raise
            except (TimeoutError, socket.timeout):
                raise GitHubError("timeout") from None
            except (OSError, http.client.HTTPException, ValueError):
                raise GitHubError("network_error") from None
            finally:
                if response is not None:
                    with suppress(Exception):
                        response.close()
                if connection is not None:
                    with suppress(Exception):
                        connection.close()
        raise GitHubError("unsafe_redirect")

    def json(self, method, path, body=None, *, upload=None, size=None, sha256=None, missing=False):
        if not path.startswith("/") or path.startswith("//"):
            raise GitHubError("unsafe_url")
        host = UPLOAD_HOST if upload is not None else API_HOST
        data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        try:
            raw, _ = self._request(method, "https://" + host + path, data=data, upload=upload, expected_size=size, expected_sha256=sha256,
                                   deadline_seconds=180 if upload is not None else 30)
        except GitHubError as exc:
            if missing and exc.http_status == 404:
                return None
            raise
        try:
            if not raw:
                return None
            return json.loads(raw)
        except (ValueError, RecursionError, UnicodeError):
            raise GitHubError("invalid_response") from None

    def pages(self, path, *, key=None):
        items = []
        for page in range(1, 11):
            data = self.json("GET", path + ("&" if "?" in path else "?") + urlencode({"per_page": 100, "page": page}))
            values = data.get(key) if key and isinstance(data, dict) else data
            if not isinstance(values, list):
                raise GitHubError("invalid_response")
            items.extend(values)
            if len(values) < 100:
                return items
        raise GitHubError("pagination_limit")

    def verify_asset(self, repository, asset, expected_hash, expected_size, *, public=False):
        asset_id = _positive_id(asset.get("id"))
        if asset.get("state") != "uploaded" or type(asset.get("size")) is not int or asset["size"] != expected_size:
            raise GitHubError("asset_conflict")
        if asset.get("digest") not in (None, "sha256:" + expected_hash):
            raise GitHubError("asset_conflict")
        digest = hashlib.sha256()
        _, size = self._request("GET", f"https://{API_HOST}/repos/{repository}/releases/assets/{asset_id}",
                                accept="application/octet-stream", authenticated=not public,
                                redirects=True, max_bytes=expected_size, sink=digest.update)
        if size != expected_size or digest.hexdigest() != expected_hash:
            raise GitHubError("asset_conflict")


def _bundle_inputs(bundle):
    from release_tools.bundle import revalidate_bundle
    from release_tools.trust import verify_approval
    try:
        checked = revalidate_bundle(bundle)
        if checked is not None:
            bundle = checked
        approval = verify_approval(bundle)
    except Exception as exc:
        raise GitHubError(getattr(exc, "code", "bundle_invalid")) from None
    _version(bundle.version)
    if not _SHA.fullmatch(bundle.source_commit) or not _SHA.fullmatch(bundle.build_commit) or set(bundle.assets) != ASSETS:
        raise GitHubError("bundle_invalid")
    expected = {}
    for name, path in bundle.assets.items():
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ASSET:
            raise GitHubError("bundle_invalid")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != bundle.manifest["assets"].get(name):
            raise GitHubError("bundle_changed")
        expected[name] = {"sha256": digest.hexdigest(), "size": path.stat().st_size}
    return bundle, expected, approval


def _commit_for_tag(client, prefix, tag):
    reference = client.json("GET", prefix + "/git/ref/tags/" + quote(tag, safe=""), missing=True)
    if reference is None:
        raise GitHubError("tag_missing")
    obj = reference.get("object") if isinstance(reference, dict) else None
    for _ in range(5):
        if not isinstance(obj, dict) or not _SHA.fullmatch(str(obj.get("sha", ""))):
            raise GitHubError("invalid_tag")
        if obj.get("type") == "commit":
            return obj["sha"]
        if obj.get("type") != "tag":
            break
        annotation = client.json("GET", prefix + "/git/tags/" + obj["sha"])
        obj = annotation.get("object") if isinstance(annotation, dict) else None
    raise GitHubError("invalid_tag")


def _no_downgrade(client, prefix, version):
    latest = client.json("GET", prefix + "/releases/latest", missing=True)
    if latest is not None:
        if not isinstance(latest, dict):
            raise GitHubError("invalid_response")
        tag = latest.get("tag_name", "")
        if not isinstance(tag, str) or not tag.startswith("v") or _version(tag[1:]) > _version(version):
            raise GitHubError("latest_downgrade")
    return latest


def _release_by_tag(client, prefix, tag):
    release = client.json("GET", prefix + "/releases/tags/" + quote(tag, safe=""), missing=True)
    if release is not None:
        if not isinstance(release, dict) or type(release.get("draft")) is not bool:
            raise GitHubError("release_conflict")
        return release
    # Some API paths expose only published tags. Reconcile authenticated drafts
    # before a non-idempotent create; a timeout must never cause blind retries.
    releases = client.pages(prefix + "/releases")
    if any(not isinstance(item, dict) for item in releases):
        raise GitHubError("invalid_response")
    matching = [item for item in releases if item.get("tag_name") == tag]
    if len(matching) > 1:
        raise GitHubError("release_conflict")
    return matching[0] if matching else None


def _remote_checks(client, bundle, repository, *, require_ci, allow_missing_tag=False, require_write=True):
    prefix = "/repos/" + repository
    # Installation tokens (including GITHUB_TOKEN) do not represent a user.
    # Their run/repository context is verified separately, without /user scope.
    profile = {"login": "github-actions[bot]"} if client.trusted_run_id is not None else client.json("GET", "/user")
    if not isinstance(profile, dict) or not isinstance(profile.get("login"), str):
        raise GitHubError("invalid_response")
    repo = client.json("GET", prefix)
    if not isinstance(repo, dict) or str(repo.get("full_name", "")).lower() != repository.lower():
        raise GitHubError("repository_mismatch")
    if repo.get("private") is not False or repo.get("archived") or repo.get("disabled"):
        raise GitHubError("public_active_repository_required")
    if require_write and client.trusted_run_id is None and (not isinstance(repo.get("permissions"), dict) or repo["permissions"].get("push") is not True):
        raise GitHubError("write_access_required")
    default = repo.get("default_branch")
    if not isinstance(default, str) or not default or len(default) > 250 or default.lower() == "staging":
        raise GitHubError("invalid_default_branch")
    tag = "v" + bundle.version
    tag_missing = False
    try:
        if _commit_for_tag(client, prefix, tag) != bundle.source_commit:
            raise GitHubError("tag_conflict")
    except GitHubError as exc:
        if exc.code != "tag_missing" or not allow_missing_tag:
            raise
        tag_missing = True
    comparison = client.json("GET", prefix + "/compare/" + bundle.source_commit + "..." + quote(default, safe=""))
    if not isinstance(comparison, dict) or comparison.get("status") not in {"identical", "ahead"}:
        raise GitHubError("approved_commit_not_in_default_branch")
    runs = client.pages(prefix + "/actions/runs?head_sha=" + bundle.source_commit, key="workflow_runs")
    active_runs = []
    for status in ("queued", "in_progress", "waiting"):
        if client.trusted_run_id is not None and status == "queued":
            # The workflow concurrency group queues later release jobs. They
            # cannot write yet and must not interrupt the current release job.
            continue
        active_runs.extend(client.pages(prefix + "/actions/workflows/build.yml/runs?status=" + status, key="workflow_runs"))
    if any(not isinstance(run, dict) for run in active_runs):
        raise GitHubError("invalid_response")
    if any(run.get("id") != client.trusted_run_id for run in active_runs):
        raise GitHubError("release_workflow_running")
    for run in runs:
        if not isinstance(run, dict):
            raise GitHubError("invalid_response")
        if run.get("path") == ".github/workflows/build.yml" and run.get("status") != "completed" and run.get("id") != client.trusted_run_id and not (client.trusted_run_id is not None and run.get("status") == "queued"):
            raise GitHubError("release_workflow_running")
    if require_ci:
        good = any(run.get("path") == ".github/workflows/windows-ci.yml" and run.get("status") == "completed" and run.get("conclusion") == "success" and run.get("event") in {"push", "workflow_dispatch"} and isinstance(run.get("head_repository"), dict) and str(run["head_repository"].get("full_name", "")).lower() == repository.lower() for run in runs)
        if not good:
            raise GitHubError("successful_trusted_ci_required")
    _no_downgrade(client, prefix, bundle.version)
    release = _release_by_tag(client, prefix, tag)
    if release is not None and (not isinstance(release, dict) or release.get("tag_name") != tag or release.get("prerelease") is not False or type(release.get("draft")) is not bool):
        raise GitHubError("release_conflict")
    return {"repository": repository, "version": bundle.version, "tag": tag, "source_commit": bundle.source_commit, "login": profile["login"], "default_branch": default, "ci_verified": bool(require_ci), "tag_missing": tag_missing}, release




def _release_assets(client, prefix, release_id):
    assets = client.pages(prefix + f"/releases/{release_id}/assets")
    by_name = {}
    for asset in assets:
        if not isinstance(asset, dict) or asset.get("name") not in ASSETS or asset["name"] in by_name:
            raise GitHubError("asset_conflict")
        by_name[asset["name"]] = asset
    return by_name


def _verify_all(client, repository, remote, expected, *, public=False):
    if set(remote) != ASSETS:
        raise GitHubError("incomplete_assets")
    for name in sorted(ASSETS):
        _check_cancel(client.cancel)
        _emit(client.emit, "verifying_public" if public else "verifying", asset=name)
        client.verify_asset(repository, remote[name], expected[name]["sha256"], expected[name]["size"], public=public)


def _notes_match(release, notes):
    body = release.get("body")
    return isinstance(body, str) and body.replace("\r\n", "\n") == notes.replace("\r\n", "\n")


def publish_github(bundle, repository, token, emit=None, cancel=None, *, require_ci=True, _client=None):
    """Resume a draft or verify an identical published release; never overwrite."""
    repository = _repository(repository)
    _check_cancel(cancel)
    bundle, expected, approval = _bundle_inputs(bundle)
    client = trusted_actions_client(repository, token, emit, cancel, _client=_client)
    if not require_ci:
        raise GitHubError("successful_trusted_ci_required")
    facts, release = _remote_checks(client, bundle, repository, require_ci=True)
    prefix = "/repos/" + repository
    created = False
    if release is None:
        _check_cancel(cancel)
        _emit(emit, "creating_draft")
        release = client.json("POST", prefix + "/releases", {"tag_name": facts["tag"],
                              "name": "TG Proxy " + facts["tag"], "body": bundle.notes, "draft": True, "prerelease": False, "make_latest": "false"})
        created = True
    if not isinstance(release, dict) or release.get("tag_name") != facts["tag"] or release.get("prerelease") is not False:
        raise GitHubError("release_conflict")
    release_id = _positive_id(release.get("id"))
    remote = _release_assets(client, prefix, release_id)
    already_published = release.get("draft") is False
    if already_published:
        if not _notes_match(release, bundle.notes):
            raise GitHubError("release_notes_conflict")
        if set(remote) != ASSETS:
            raise GitHubError("published_release_incomplete")
    else:
        if release.get("draft") is not True or release.get("immutable") is True:
            raise GitHubError("release_conflict")
        for name in sorted(ASSETS):
            _check_cancel(cancel)
            if name in remote:
                client.verify_asset(repository, remote[name], expected[name]["sha256"], expected[name]["size"])
                continue
            # Re-read all local hashes immediately before each mutation.
            _, current, _ = _bundle_inputs(bundle)
            if current != expected:
                raise GitHubError("bundle_changed")
            path = Path(bundle.assets[name])
            client.json("POST", prefix + f"/releases/{release_id}/assets?" + urlencode({"name": name}), upload=path, size=expected[name]["size"], sha256=expected[name]["sha256"])
        remote = _release_assets(client, prefix, release_id)
        _verify_all(client, repository, remote, expected)
        _check_cancel(cancel)
        # Another release job must not have advanced latest/tag while uploads ran.
        _no_downgrade(client, prefix, bundle.version)
        if _commit_for_tag(client, prefix, facts["tag"]) != bundle.source_commit:
            raise GitHubError("tag_conflict")
        _emit(emit, "publishing")
        release = client.json("PATCH", prefix + f"/releases/{release_id}", {"draft": False, "prerelease": False, "make_latest": "true", "body": bundle.notes})
        if not isinstance(release, dict) or release.get("draft") is not False or release.get("tag_name") != facts["tag"]:
            raise GitHubError("invalid_response")
        if not _notes_match(release, bundle.notes):
            raise GitHubError("release_notes_conflict")
    remote = _release_assets(client, prefix, release_id)
    _verify_all(client, repository, remote, expected, public=True)
    if _commit_for_tag(client, prefix, facts["tag"]) != bundle.source_commit:
        raise GitHubError("tag_conflict")
    latest = _no_downgrade(client, prefix, bundle.version)
    if latest is None or latest.get("tag_name") != facts["tag"]:
        raise GitHubError("latest_not_confirmed")
    report = {**facts, "status": "already_published" if already_published else "published", "release_url": f"https://github.com/{repository}/releases/tag/{facts['tag']}",
              "assets": expected, "bundle_id": bundle.bundle_id, "verified": True, "created_draft": created}
    _emit(emit, "complete")
    return report


# Wire identifiers retained for already distributed signed-bundle senders.
# This module does not prepare input drafts, dispatch workflows or store keys.
WORKFLOW_MARKER = "TGPROXY_EXACT_BUNDLE_PUBLISHER_V1"
INPUT_ASSET = "publication-bundle.zip"
MAX_BUNDLE_ARCHIVE = 600 * 1024 * 1024
_BUNDLE_FILES = {"manifest.json", "source.zip", "RELEASE_NOTES.md", "approval.json"} | {"assets/" + name for name in ASSETS}






def download_draft_archive(repository, token, release_id, asset_id, expected_sha256, archive_path, *, cancel=None, emit=None, _client=None):
    """Fetch one bounded immutable raw ZIP; never extract or execute its contents."""
    repository = _repository(repository)
    release_id, asset_id = _positive_id(release_id), _positive_id(asset_id)
    if not isinstance(expected_sha256, str) or _DIGEST.fullmatch(expected_sha256) is None:
        raise GitHubError("invalid_workflow_input")
    archive_path = Path(archive_path)
    if archive_path.exists() or archive_path.is_symlink():
        raise GitHubError("output_exists")
    client = _client or GitHubClient(token, cancel=cancel, emit=emit)
    prefix = "/repos/" + repository
    try:
        draft = client.json("GET", prefix + f"/releases/{release_id}")
    except GitHubError as exc:
        exc.input_endpoint = InputEndpoint.DRAFT_METADATA
        raise
    tag = draft.get("tag_name") if isinstance(draft, dict) else None
    match = re.fullmatch(r"publisher-input-([0-9a-f]{64})", tag) if type(tag) is str else None
    if not isinstance(draft, dict) or draft.get("draft") is not True or match is None:
        raise GitHubError("draft_input_required")
    try:
        assets = client.pages(prefix + f"/releases/{release_id}/assets")
    except GitHubError as exc:
        exc.input_endpoint = InputEndpoint.ASSET_METADATA
        raise
    if len(assets) != 1 or assets[0].get("id") != asset_id or assets[0].get("name") != INPUT_ASSET:
        raise GitHubError("draft_input_conflict")
    size = assets[0].get("size")
    if type(size) is not int or not 0 < size <= MAX_BUNDLE_ARCHIVE:
        raise GitHubError("bundle_too_large")
    digest = hashlib.sha256()
    with archive_path.open("xb") as destination:
        def save(data):
            destination.write(data)
            digest.update(data)
        try:
            _, count = client._request("GET", f"https://{API_HOST}{prefix}/releases/assets/{asset_id}", accept="application/octet-stream", redirects=True, max_bytes=size, sink=save)
        except GitHubError as exc:
            exc.input_endpoint = InputEndpoint.ASSET_DOWNLOAD
            raise
    if count != size or digest.hexdigest() != expected_sha256:
        raise GitHubError("draft_input_hash")
    return match.group(1)


def load_local_bundle_archive(archive_path, expected_sha256, expected_bundle_id, output, *, cancel=None):
    """Hash a private snapshot, then validate exact eight data files and approval."""
    from release_tools.bundle import load_bundle
    from release_tools.trust import verify_approval
    if (not isinstance(expected_sha256, str) or _DIGEST.fullmatch(expected_sha256) is None
            or not isinstance(expected_bundle_id, str) or _DIGEST.fullmatch(expected_bundle_id) is None):
        raise GitHubError("invalid_workflow_input")
    archive_path, output = Path(archive_path), Path(output)
    if output.exists() or output.is_symlink():
        raise GitHubError("output_exists")
    try:
        metadata = archive_path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or archive_path.is_symlink()
                or not 0 < metadata.st_size <= MAX_BUNDLE_ARCHIVE):
            raise GitHubError("bundle_archive")
        # Extraction uses these exact hashed bytes, even if an artifact path
        # changes concurrently after validation. Downloaded code is never run.
        with tempfile.TemporaryFile(mode="w+b") as snapshot:
            digest, count = hashlib.sha256(), 0
            with archive_path.open("rb") as raw:
                while chunk := raw.read(64 * 1024):
                    _check_cancel(cancel)
                    count += len(chunk)
                    if count > MAX_BUNDLE_ARCHIVE:
                        raise GitHubError("bundle_too_large")
                    digest.update(chunk)
                    snapshot.write(chunk)
            if count != metadata.st_size or digest.hexdigest() != expected_sha256:
                raise GitHubError("draft_input_hash")
            snapshot.seek(0)
            output.mkdir(parents=True)
            try:
                with zipfile.ZipFile(snapshot) as archive:
                    entries = archive.infolist()
                    if len(entries) != 8 or {item.filename for item in entries} != _BUNDLE_FILES or sum(item.file_size for item in entries) > MAX_BUNDLE_ARCHIVE:
                        raise GitHubError("bundle_archive")
                    for item in entries:
                        _check_cancel(cancel)
                        if item.is_dir() or item.flag_bits & 1 or ((item.external_attr >> 16) & 0o170000) not in (0, 0o100000) or item.file_size > MAX_ASSET:
                            raise GitHubError("bundle_archive")
                        path = output / item.filename
                        path.parent.mkdir(parents=True, exist_ok=True)
                        with archive.open(item) as source, path.open("xb") as destination:
                            written = 0
                            while chunk := source.read(64 * 1024):
                                _check_cancel(cancel)
                                written += len(chunk)
                                if written > item.file_size:
                                    raise GitHubError("bundle_archive")
                                destination.write(chunk)
                bundle = load_bundle(output)
                verify_approval(bundle)
            except GitHubError:
                raise
            except Exception as exc:
                raise GitHubError(getattr(exc, "code", "bundle_archive")) from None
    except GitHubError:
        raise
    except Exception as exc:
        raise GitHubError(getattr(exc, "code", "bundle_archive")) from None
    if bundle.bundle_id != expected_bundle_id:
        raise GitHubError("draft_input_conflict")
    return bundle


def download_draft_bundle(repository, token, release_id, asset_id, expected_sha256, output, *, cancel=None, emit=None, _client=None):
    """Legacy combined path; all guards are shared with artifact-based jobs."""
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise GitHubError("output_exists")
    archive_path = output.parent / (output.name + ".input.zip")
    bundle_id = download_draft_archive(repository, token, release_id, asset_id,
        expected_sha256, archive_path, cancel=cancel, emit=emit, _client=_client)
    return load_local_bundle_archive(archive_path, expected_sha256, bundle_id, output, cancel=cancel)



def trusted_actions_client(repository, token, emit=None, cancel=None, *, _client=None):
    """Only a successful API-verified default-branch manual workflow may bootstrap."""
    repository = _repository(repository)
    env = os.environ
    if env.get("GITHUB_ACTIONS") != "true" or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or env.get("GITHUB_REPOSITORY") != repository or not str(env.get("GITHUB_RUN_ID", "")).isdigit():
        raise GitHubError("trusted_actions_context_required")
    client = _client or GitHubClient(token, cancel=cancel, emit=emit)
    repo = client.json("GET", "/repos/" + repository)
    if not isinstance(repo, dict):
        raise GitHubError("invalid_response")
    default = repo.get("default_branch")
    sha = env.get("GITHUB_SHA", "")
    if not isinstance(default, str) or env.get("GITHUB_REF") != "refs/heads/" + default or not _SHA.fullmatch(sha):
        raise GitHubError("trusted_actions_context_required")
    run_id = int(env["GITHUB_RUN_ID"])
    run = client.json("GET", "/repos/" + repository + f"/actions/runs/{run_id}")
    if not isinstance(run, dict) or run.get("path") != ".github/workflows/build.yml" or run.get("event") != "workflow_dispatch" or run.get("head_sha") != sha or run.get("head_branch") != default or not isinstance(run.get("head_repository"), dict) or str(run["head_repository"].get("full_name", "")).lower() != repository.lower():
        raise GitHubError("trusted_actions_context_required")
    client.trusted_run_id = run_id
    return client


def create_missing_tag_for_actions(bundle, repository, token, emit=None, cancel=None, *, _client=None):
    """Create once only after verifying the trusted Actions run context."""
    bundle, _, _ = _bundle_inputs(bundle)
    client = trusted_actions_client(repository, token, emit, cancel, _client=_client)
    facts, _ = _remote_checks(client, bundle, repository, require_ci=True, allow_missing_tag=True)
    if facts["tag_missing"]:
        _check_cancel(cancel)
        client.json("POST", "/repos/" + repository + "/git/refs", {"ref": "refs/tags/" + facts["tag"], "sha": bundle.source_commit})
        if _commit_for_tag(client, "/repos/" + repository, facts["tag"]) != bundle.source_commit:
            raise GitHubError("tag_conflict")
    return {"status": "tag_verified", "tag": facts["tag"], "source_commit": bundle.source_commit}


def verify_workflow_bundle(bundle, repository, token, emit=None, cancel=None, *, _client=None):
    bundle, expected, _ = _bundle_inputs(bundle)
    client = trusted_actions_client(repository, token, emit, cancel, _client=_client)
    facts, _ = _remote_checks(client, bundle, repository, require_ci=True, allow_missing_tag=True, require_write=False)
    return {**facts, "status": "verified", "bundle_id": bundle.bundle_id, "assets": expected, "approval_verified": True}
