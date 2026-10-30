"""GitHub-first release discovery with a signed backup and verified downloads."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import tempfile
import time
from contextlib import suppress
from http.client import HTTPException
from itertools import zip_longest
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request

from proxy.http_transport import response_with_deadline as _response_with_deadline
from proxy.utils import build_github_opener
from proxy.project import REPOSITORY as REPO
from utils.update_manifest import (
    MAX_ASSET_BYTES, MAX_MANIFEST_BYTES, validate_https_url, verify_manifest,
    version_gt as _semver_gt,
)

try:
    from proxy.update_channel import UPDATE_MANIFEST_URL, TRUSTED_UPDATE_KEYS
except ImportError:
    UPDATE_MANIFEST_URL, TRUSTED_UPDATE_KEYS = "", {}

RELEASES_LATEST_API = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE_URL = f"https://github.com/{REPO}/releases/latest"
log = logging.getLogger("tg-updater")

_SHA256 = re.compile(r"sha256:([0-9a-f]{64})", re.IGNORECASE)
_GITHUB_VERSION = re.compile(r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){1,2}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
_state: Dict[str, Any] = {
    "checked": False,
    "has_update": False,
    "ahead_of_release": False,
    "latest": None,
    "html_url": RELEASES_PAGE_URL,
    "error": None,
    "http_status": None,
    "assets": [],
    "source": None,
    "github_result": None,
}


def _parse_version_tuple(s: str) -> tuple:
    parts = []
    for part in (s or "").strip().lstrip("vV").split("."):
        match = re.match(r"\d+", part)
        parts.append(int(match[0]) if match else 0)
    return tuple(parts)


def _version_gt(a: str, b: str) -> bool:
    try:
        return _semver_gt(a, b)
    except ValueError:
        pass  # Preserve old GitHub tags such as v2.0 and legacy suffixes.
    for x, y in zip_longest(_parse_version_tuple(a), _parse_version_tuple(b), fillvalue=0):
        if x != y:
            return x > y
    return False


class _HTTPSOnlyRedirect(HTTPRedirectHandler):
    handler_order = 100  # Run before urllib's default redirect handler.

    def http_error_302(self, req, fp, code, msg, headers):
        # urllib otherwise drains the entire redirect body with read() before
        # following Location, bypassing our response/download size limits.
        # These connections are not reused. A closed HTTPResponse.read()
        # returns b"", so retain urllib's redirect policy without that drain.
        # Close before URL parsing as rejected redirects must release it too.
        fp.close()
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _secure_opener(response_timeout=12.0):
    # One deadline is shared by redirects and the pinned-address DNS fallback.
    deadline = time.monotonic() + response_timeout
    response_class = _response_with_deadline(deadline)
    opener = build_github_opener(response_class=response_class, connection_deadline=deadline)
    opener.add_handler(_HTTPSOnlyRedirect())
    return opener


def _open_response(request, *, timeout, response_timeout):
    try:
        return _secure_opener(response_timeout).open(request, timeout=timeout)
    except HTTPError as error:
        # An HTTPError owns its response body. It never enters the caller's
        # with statement, so release its socket and watchdog explicitly.
        error.close()
        raise


def _response_url(response, requested):
    geturl = getattr(response, "geturl", None)
    validate_https_url(geturl() if callable(geturl) else requested)


def _read_chunk(response, size):
    # HTTPResponse.read(size) waits for the entire block and resets the socket
    # inactivity timeout on every received byte. A trickling server could thus
    # keep it inside one read indefinitely, bypassing our elapsed-time checks.
    # read1 performs at most one body read so those checks run between packets.
    read = getattr(response, "read1", None)
    return read(size) if callable(read) else response.read(size)


def _read_bounded(response, limit, timeout):
    deadline, chunks, count = time.monotonic() + timeout, [], 0
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("Update request exceeded its time limit")
        chunk = _read_chunk(response, min(65536, limit + 1 - count))
        if not chunk:
            return b"".join(chunks)
        count += len(chunk)
        if count > limit:
            raise ValueError("Update response exceeds its size limit")
        chunks.append(chunk)


def fetch_latest_release(timeout: float = 12.0) -> dict:
    req = Request(RELEASES_LATEST_API, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "tg-ws-proxy-update-check",
    })
    with _open_response(req, timeout=timeout, response_timeout=timeout) as resp:
        _response_url(resp, RELEASES_LATEST_API)
        try:
            return json.loads(_read_bounded(resp, MAX_MANIFEST_BYTES, timeout))
        except RecursionError:
            raise ValueError("GitHub release JSON is nested too deeply") from None


def fetch_backup_release(server_url: str, timeout: float = 12.0) -> dict:
    validate_https_url(server_url)
    req = Request(server_url, headers={"Accept": "application/json", "User-Agent": "tg-ws-proxy-update-check"})
    with _open_response(req, timeout=timeout, response_timeout=timeout) as resp:
        _response_url(resp, server_url)
        return verify_manifest(_read_bounded(resp, MAX_MANIFEST_BYTES, timeout), TRUSTED_UPDATE_KEYS)


def _extract_assets(data: dict) -> list:
    assets = (data or {}).get("assets")
    if assets is None:
        assets = []
    if not isinstance(assets, list):
        raise ValueError("Invalid release assets from GitHub")
    return [
        {"name": a["name"], "url": a["browser_download_url"],
         "digest": a.get("digest") if isinstance(a.get("digest"), str) else ""}
        for a in assets
        if isinstance(a, dict) and isinstance(a.get("name"), str) and a["name"]
        and isinstance(a.get("browser_download_url"), str) and a["browser_download_url"]
    ]


def _compatible_asset_names():
    if sys.platform == "win32":
        from utils.windows_update import asset_name
        return {asset_name()}
    if sys.platform.startswith("linux"):
        return {"TgWsProxy_linux_amd64", "TgWsProxy_linux_amd64.deb", "TgWsProxy_linux_amd64.rpm"}
    return set()


def _installable(assets):
    names = _compatible_asset_names()
    return any(a.get("name") in names and _valid_asset(a) for a in assets)


def _valid_asset(asset):
    try:
        validate_https_url(asset.get("url"))
    except ValueError:
        return False
    digest = asset.get("digest")
    return isinstance(digest, str) and bool(_SHA256.fullmatch(digest))


def _log_version(value) -> str:
    """Do not let unexpected version inputs inject text or secrets into logs."""
    if isinstance(value, str) and len(value) <= 128:
        version = value.strip().lstrip("vV")
        if _GITHUB_VERSION.fullmatch(version):
            return version
    return "неизвестна"


def _failure_reason(error) -> str:
    """Expose useful categories without exception text, URLs or response data."""
    code = getattr(error, "code", None)
    if type(code) is int and 100 <= code <= 599:
        return f"HTTP {code}"
    if isinstance(error, TimeoutError) or isinstance(getattr(error, "reason", None), TimeoutError):
        return "истекло время ожидания"
    if isinstance(error, ValueError):
        return "данные отклонены при проверке"
    if isinstance(error, HTTPException):
        return "некорректный HTTP-ответ"
    return "ошибка сети"


def _log_check_result(state, current_version):
    if state["error"] is not None:
        log.error("Проверка обновлений завершена: не удалось получить сведения об обновлениях")
        return
    if state.get("github_result") == "no_public_release" and not state.get("latest"):
        log.info("Проверка обновлений завершена: публичный стабильный релиз GitHub недоступен")
        return
    source = "GitHub" if state["source"] == "github" else "резервный сервер"
    current, latest = _log_version(current_version), _log_version(state["latest"])
    if state["has_update"]:
        log.info("Проверка обновлений завершена: доступна версия %s "
                 "(установлена %s; источник: %s)", latest, current, source)
    elif state["ahead_of_release"]:
        log.info("Проверка обновлений завершена: установленная версия %s новее "
                 "опубликованной %s (источник: %s)", current, latest, source)
    else:
        log.info("Проверка обновлений завершена: обновлений не найдено "
                 "(установлена версия %s; источник: %s)", current, source)


def run_check(current_version: str, server_url: Optional[str] = None) -> None:
    """Publish the complete result at once; no persistent cache or error cooldown."""
    global _state
    state = {
        "checked": True, "has_update": False, "ahead_of_release": False,
        "latest": None, "html_url": RELEASES_PAGE_URL, "error": None,
        "http_status": None, "assets": [], "source": None,
        "github_result": None,
    }
    backup_url = UPDATE_MANIFEST_URL if server_url is None else server_url
    primary, primary_error = None, None
    log.info("Проверка обновлений: текущая версия %s", _log_version(current_version))
    log.info("Проверка обновлений: обращаемся к GitHub")
    try:
        data = fetch_latest_release()
        if not isinstance(data, dict) or not isinstance(data.get("tag_name"), str):
            raise ValueError("Invalid release from GitHub")
        latest = data["tag_name"].strip().lstrip("vV")
        if len(latest) > 128 or not _GITHUB_VERSION.fullmatch(latest):
            raise ValueError("Invalid release version from GitHub")
        primary = dict(
            latest=latest,
            has_update=_version_gt(latest, current_version),
            ahead_of_release=_version_gt(current_version, latest),
            html_url=data.get("html_url") or RELEASES_PAGE_URL,
            assets=_extract_assets(data), source="github",
        )
        validate_https_url(primary["html_url"])
        for asset in primary["assets"]:
            asset.update(version=latest, source="github")
            if type(data.get("assets")) is list:
                original = next((a for a in data["assets"] if isinstance(a, dict) and a.get("name") == asset["name"]), {})
                size = original.get("size")
                if type(size) is int and 0 < size <= MAX_ASSET_BYTES:
                    asset["size"] = size
        log.info("GitHub: опубликована версия %s", _log_version(latest))
        state["github_result"] = "release_available"
    except (OSError, ValueError, HTTPException) as exc:
        primary = None
        primary_error = exc
        if isinstance(exc, HTTPError) and exc.code == 404:
            # /releases/latest returns 404 both for a hidden repository and
            # when no public, non-prerelease release exists. It is an HTTP
            # response, not evidence that a connection could not be made.
            state["github_result"] = "no_public_release"
            log.info("GitHub ответил HTTP 404: публичный стабильный релиз недоступен")
        else:
            state["github_result"] = "check_failed"
            log.warning("Проверка GitHub не удалась (%s)", _failure_reason(exc))
    chosen = primary
    need_backup = primary is None or not primary["has_update"] or not _installable(primary["assets"])
    if backup_url and need_backup:
        if state["github_result"] == "no_public_release":
            reason = "публичный стабильный релиз GitHub недоступен"
        elif primary is None:
            reason = "проверка GitHub не удалась"
        elif not primary["has_update"]:
            reason = "на GitHub нет более новой версии для этого клиента"
        else:
            reason = "на GitHub нет подходящего проверяемого файла установки"
        log.info("Проверка обновлений: обращаемся к резервному серверу — %s", reason)
        try:
            backup = fetch_backup_release(backup_url)
            latest = backup["latest"]
            log.info("Резервный сервер: подпись манифеста проверена; версия %s", _log_version(latest))
            backup.update(has_update=_version_gt(latest, current_version),
                          ahead_of_release=_version_gt(current_version, latest))
            if (primary is None or _version_gt(latest, primary["latest"])
                    or (not _version_gt(primary["latest"], latest)
                        and backup["has_update"] and _installable(backup["assets"])
                        and not _installable(primary["assets"]))):
                chosen = backup
            else:
                log.info("Проверка обновлений: сохраняем результат GitHub; "
                         "резервный сервер не предлагает предпочтительного релиза")
        except (OSError, ValueError, HTTPException) as exc:
            if primary is None:
                primary_error = exc
            log.warning("Проверка резервного сервера не удалась (%s)", _failure_reason(exc))
    if chosen is not None:
        state.update(chosen)
        # Immutable snapshots carry enough context for a later download retry.
        for asset in state["assets"]:
            asset.update(current_version=current_version, manifest_url=backup_url)
    elif state["github_result"] == "no_public_release" and not backup_url:
        state.update(http_status=404, source="github")
    elif primary_error is not None:
        state["error"] = str(primary_error) or type(primary_error).__name__
        exc = primary_error
        code = getattr(exc, "code", None)
        state["http_status"] = code if isinstance(code, int) else None
    _state = state
    _log_check_result(state, current_version)


def _notify(callback, *arguments):
    if callback is not None:
        try:
            callback(*arguments)
        except Exception:
            pass  # Presentation callbacks cannot change verified download behavior.


class _DownloadProgress:
    def __init__(self, callback, total):
        self.callback = callback
        self.total = total
        self.last = None
        self.finished = False

    def emit(self, count, *, force=False):
        if self.callback is None:
            return
        now = time.monotonic()
        if force or self.last is None or now - self.last >= .1:
            self.last = now
            _notify(self.callback, count, self.total)

    def finish(self, count):
        if not self.finished:
            self.finished = True
            self.emit(count, force=True)


def download_asset(
    url: str, dest_dir: Path, suffix: str = ".tmp", digest: str = "",
    timeout: float = 30.0,
    size: Optional[int] = None,
    *, progress: Optional[Callable[[int, Optional[int]], None]] = None,
    on_verifying: Optional[Callable[[], None]] = None,
) -> Path:
    """Return a temporary file only after its mandatory SHA-256 has matched."""
    expected = _SHA256.fullmatch(digest if isinstance(digest, str) else "")
    if not expected:
        raise ValueError("The release asset has no valid SHA-256 checksum")
    validate_https_url(url)
    if size is not None and (type(size) is not int or not 1 <= size <= MAX_ASSET_BYTES):
        raise ValueError("Invalid release asset size")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 300:
        raise ValueError("Invalid update timeout")

    fd, name = tempfile.mkstemp(dir=str(dest_dir), suffix=suffix, prefix="TgWsProxy_tmp_")
    path = Path(name)
    reporter = _DownloadProgress(progress, size)
    count = 0
    try:
        reporter.emit(0, force=True)
        sha = hashlib.sha256()
        deadline = time.monotonic() + 300
        with os.fdopen(fd, "wb") as out, _open_response(url, timeout=timeout, response_timeout=300) as resp:
            _response_url(resp, url)
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Update download exceeded its time limit")
                chunk = _read_chunk(resp, 65536)
                if not chunk:
                    break
                count += len(chunk)
                if count > (size if size is not None else MAX_ASSET_BYTES):
                    raise OSError("Release asset exceeds its expected size")
                out.write(chunk)
                sha.update(chunk)
                reporter.emit(count)
        reporter.finish(count)
        _notify(on_verifying)
        if size is not None and count != size:
            raise OSError("Release asset size does not match")
        if sha.hexdigest() != expected[1].lower():
            raise OSError("SHA-256 checksum does not match the release asset")
        return path
    except BaseException:
        reporter.finish(count)
        with suppress(OSError):
            path.unlink()
        raise


def download_release_asset(
    asset: dict, dest_dir: Path, suffix: str = ".tmp", timeout: float = 30.0,
    *, progress: Optional[Callable[[int, Optional[int]], None]] = None,
    on_verifying: Optional[Callable[[], None]] = None,
    on_candidate: Optional[Callable[[dict], None]] = None,
):
    """Return (verified file, actual metadata), retrying a failed GitHub asset.

    The fallback can never downgrade the requested release or the installed app.
    Callers must use the returned metadata for any subsequent verification.
    """
    asset = dict(asset)
    if asset.get("version") and asset.get("current_version") and not _version_gt(asset["version"], asset["current_version"]):
        raise ValueError("The release is not newer than the installed application")

    def download(candidate):
        _notify(on_candidate, dict(candidate))
        callbacks = {}
        if progress is not None:
            callbacks["progress"] = progress
        if on_verifying is not None:
            callbacks["on_verifying"] = on_verifying
        return download_asset(candidate["url"], dest_dir, suffix=suffix,
                              digest=candidate["digest"], timeout=timeout, size=candidate.get("size"), **callbacks)

    try:
        return download(asset), dict(asset)
    except (OSError, ValueError, HTTPException):
        url = asset.get("manifest_url") or UPDATE_MANIFEST_URL
        if asset.get("source") != "github" or not url:
            raise
        backup = fetch_backup_release(url)
        version, requested, current = backup["latest"], asset.get("version"), asset.get("current_version")
        if not requested or not current or _version_gt(requested, version) or not _version_gt(version, current):
            raise ValueError("The backup release would downgrade the requested update") from None
        for candidate in backup["assets"]:
            if candidate["name"] == asset["name"]:
                candidate.update(current_version=current, manifest_url=url)
                return download(candidate), dict(candidate)
        raise ValueError("The backup has no compatible release asset") from None


def find_asset(name: str) -> Optional[Dict[str, Any]]:
    """Find an asset suitable for automatic installation."""
    for asset in _state["assets"]:
        if asset.get("name") == name and _valid_asset(asset):
            if asset.get("version") and asset.get("current_version") and not _version_gt(asset["version"], asset["current_version"]):
                return None
            return dict(asset)
    return None


def get_status() -> Dict[str, Any]:
    state = _state
    return {**state, "assets": [dict(a) for a in state["assets"]]}


def relaunch_env() -> Dict[str, str]:
    """Use system libraries and unpack a fresh bundle with PyInstaller 5 or 6."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("_PYI_", "_MEIPASS"))}
    mei = getattr(sys, "_MEIPASS", None)
    if mei:
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    for var in ("PATH", "LD_LIBRARY_PATH", "GI_TYPELIB_PATH", "GTK_PATH",
                "GST_PLUGIN_PATH", "GIO_MODULE_DIR"):
        original = env.pop(var + "_ORIG", None)
        if original is not None:
            env[var] = original
        elif mei and env.get(var):
            bundle = os.path.normcase(os.path.abspath(mei))
            kept = [p for p in env[var].split(os.pathsep)
                    if not (os.path.normcase(os.path.abspath(p)) + os.sep).startswith(bundle + os.sep)]
            if kept:
                env[var] = os.pathsep.join(kept)
            else:
                env.pop(var, None)
    return env
