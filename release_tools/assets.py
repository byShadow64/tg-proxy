"""Read-only validation of the four prepared release assets.

No private signing key, credential store, SFTP or server upload code lives here.
"""
from __future__ import annotations
import hashlib
import io
import re
import stat
import zipfile
from pathlib import Path
from typing import Mapping

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


_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?")


_PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")


class PublicationError(RuntimeError):
    """A non-sensitive error code, safe for CLI and automation output."""

    def __init__(self, code: str):
        self.code = code
        super().__init__("Update publication failed (" + code + ")")


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
