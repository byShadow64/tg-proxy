"""Strict, non-executing validation of an immutable prepared release folder."""
from __future__ import annotations

import ast
import hashlib
import json
import re
import stat
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Mapping

from release_tools import assets as core


ASSET_NAMES = ("CHANGELOG.md", "SHA256SUMS.txt", "TgWsProxy_helper.zip", "TgWsProxy_windows.exe")
MAX_MANIFEST = 1024 * 1024
MAX_SOURCE_ZIP = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_FILE = 16 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_PROHIBITED = frozenset({"ui/connection_diagnostics.py", "utils/connection_diagnostics.py",
                         "private_progress_probe.py", "PRIVATE_DO_NOT_PUBLISH.json"})
_PRODUCTION_DIAGNOSTICS = frozenset({"ui/connection_diagnostics.py", "utils/connection_diagnostics.py"})
_ALWAYS_PROHIBITED = frozenset(name.casefold() for name in _PROHIBITED - _PRODUCTION_DIAGNOSTICS)


def _production_diagnostics_allowed(version):
    """The reviewed diagnostics become production source starting at 1.15.0.

    This is a source-content rule only, never an approval or publication gate.
    Callers without an explicitly validated stable version keep the old policy.
    """
    if not isinstance(version, str) or len(version) > 128:
        return False
    match = _STABLE.fullmatch(version)
    return bool(match and tuple(int(part) for part in match.groups()) >= (1, 15, 0))


class BundleError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__("Release bundle validation failed (" + code + ")")


@dataclass(frozen=True)
class ReleaseBundle:
    root: Path
    version: str
    assets: Mapping[str, Path]
    notes: str
    source_zip: Path
    source_commit: str
    build_commit: str
    manifest: dict
    bundle_id: str
    asset_sizes: Mapping[str, int] = field(default_factory=dict)
    manifest_sha256: str = ""

    @property
    def path(self):
        return self.root


def canonical_json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def hash_file(path: Path, *, maximum: int | None = None) -> str:
    digest, count = hashlib.sha256(), 0
    with Path(path).open("rb") as source:
        while chunk := source.read(256 * 1024):
            count += len(chunk)
            if maximum is not None and count > maximum:
                raise BundleError("file_size")
            digest.update(chunk)
    return digest.hexdigest()


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise BundleError("duplicate_json")
        value[key] = item
    return value


def _regular(path: Path, maximum: int, *, allow_empty=False):
    try:
        meta = path.lstat()
        if (not stat.S_ISREG(meta.st_mode) or path.is_symlink()
                or getattr(path, "is_junction", lambda: False)()
                or meta.st_size > maximum or (not allow_empty and meta.st_size == 0)):
            raise BundleError("file_type")
    except OSError:
        raise BundleError("missing_file") from None


def _source_name(value, *, version=None):
    if (not isinstance(value, str) or not value or len(value) > 512
            or "\\" in value or ":" in value or "\x00" in value
            or any(ord(c) < 32 for c in value)):
        raise BundleError("source_path")
    name = PurePosixPath(value)
    # Windows normalizes trailing dots/spaces on ordinary filesystem access.
    # Reject aliases before version/content rules or a blocked canonical name
    # could be admitted under a different archive spelling.
    if name.is_absolute() or any(p in ("", ".", "..") or p.endswith((".", " "))
                                for p in value.split("/")):
        raise BundleError("source_path")
    parts = {p.casefold() for p in name.parts}
    diagnostic = value.casefold() in _PRODUCTION_DIAGNOSTICS
    diagnostic_allowed = value in _PRODUCTION_DIAGNOSTICS and _production_diagnostics_allowed(version)
    if (parts.intersection({".venv", "venv", "__pycache__", "tgwsproxy_data",
                            "dist", "build", ".git", "private-update-client", "private-progress-client"})
            or (diagnostic and not diagnostic_allowed)
            or value.casefold() in _ALWAYS_PROHIBITED
            or "private_do_not_publish" in value.casefold()
            or name.suffix.lower() in {".exe", ".pyc", ".key", ".pem", ".pfx", ".p12", ".log"}
            or name.name.casefold() in {".env", "publisher.dpapi.json", "config.json"}
            or name.name.casefold().endswith(".dpapi.json")):
        raise BundleError("private_or_test_source")
    return value


def _source_version(data):
    try:
        tree = ast.parse(data.decode("utf-8-sig"))
        versions = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets)
                    and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
        if len(versions) != 1:
            raise ValueError
        return versions[0]
    except (ValueError, SyntaxError, UnicodeError):
        raise BundleError("source_version") from None


def load_bundle(path) -> ReleaseBundle:
    """Validate every byte; never unpack, import or run bundle source or EXE.

    Integrity does not imply approval: release promotion additionally requires the
    separately verified release approval from release_tools.trust.
    """
    try:
        supplied = Path(path).expanduser()
        if supplied.name == "manifest.json" and supplied.is_file():
            supplied = supplied.parent
        if supplied.is_symlink() or getattr(supplied, "is_junction", lambda: False)():
            raise BundleError("directory_type")
        root = supplied.resolve(strict=True)
        if not root.is_dir():
            raise BundleError("directory_type")
        entries = {p.name for p in root.iterdir()}
        if not {"manifest.json", "source.zip", "RELEASE_NOTES.md", "assets"}.issubset(entries):
            raise BundleError("layout")
        if entries - {"manifest.json", "source.zip", "RELEASE_NOTES.md", "assets", "approval.json"}:
            raise BundleError("unexpected_bundle_file")
        _regular(root / "manifest.json", MAX_MANIFEST)
        raw_manifest = (root / "manifest.json").read_bytes()
        manifest = json.loads(raw_manifest.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(BundleError("json_number")))
        if not isinstance(manifest, dict):
            raise BundleError("manifest")
        allowed = {"schema", "version", "created_at", "base_commit", "build_commit", "source_commit",
                   "files", "assets", "source_zip_sha256", "release_ready", "do_not_publish",
                   "PRIVATE_DO_NOT_PUBLISH", "private_fixture", "candidate_only", "staging"}
        if set(manifest) - allowed:
            raise BundleError("manifest_fields")
        if "schema" in manifest and (type(manifest["schema"]) is not int or manifest["schema"] != 1):
            raise BundleError("manifest")
        for flag in ("do_not_publish", "PRIVATE_DO_NOT_PUBLISH", "private_fixture", "candidate_only", "staging"):
            if flag in manifest and type(manifest[flag]) is not bool:
                raise BundleError("manifest")
        if "base_commit" in manifest and (not isinstance(manifest["base_commit"], str)
                                          or _COMMIT.fullmatch(manifest["base_commit"]) is None):
            raise BundleError("commit")
        if "created_at" in manifest:
            value = manifest["created_at"]
            if (not isinstance(value, str) or len(value) > 64
                    or datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None):
                raise BundleError("manifest")
        version = manifest.get("version")
        if not isinstance(version, str) or _STABLE.fullmatch(version) is None:
            raise BundleError("stable_version")
        if (manifest.get("release_ready") is not True or manifest.get("do_not_publish")
                or manifest.get("PRIVATE_DO_NOT_PUBLISH") or manifest.get("private_fixture")
                or manifest.get("candidate_only") or manifest.get("staging")):
            raise BundleError("not_approved_stable")
        for key in ("source_commit", "build_commit"):
            if not isinstance(manifest.get(key), str) or _COMMIT.fullmatch(manifest[key]) is None:
                raise BundleError("commit")
        source_hash = manifest.get("source_zip_sha256")
        if not isinstance(source_hash, str) or _HASH.fullmatch(source_hash) is None:
            raise BundleError("source_hash")
        hashes = manifest.get("assets")
        if (not isinstance(hashes, dict) or set(hashes) != set(ASSET_NAMES)
                or any(not isinstance(h, str) or _HASH.fullmatch(h) is None for h in hashes.values())):
            raise BundleError("asset_allowlist")
        asset_root = root / "assets"
        if (asset_root.is_symlink() or getattr(asset_root, "is_junction", lambda: False)()
                or not asset_root.is_dir() or {p.name for p in asset_root.iterdir()} != set(ASSET_NAMES)):
            raise BundleError("asset_allowlist")
        assets = {name: asset_root / name for name in ASSET_NAMES}
        for name, file in assets.items():
            _regular(file, core.MAX_ASSET_BYTES[name])
            if hash_file(file, maximum=core.MAX_ASSET_BYTES[name]) != hashes[name]:
                raise BundleError("asset_hash")
        try:
            captured_assets = core._read_release_files(version, assets)
        except core.PublicationError as error:
            raise BundleError(error.code) from None
        # The parser's second read must still be the exact approved content,
        # rather than a replacement made after the initial streaming hash.
        if any(hashlib.sha256(data).hexdigest() != hashes[name]
               for name, data in captured_assets.items()):
            raise BundleError("asset_hash")
        asset_sizes = {name: len(data) for name, data in captured_assets.items()}
        source_zip = root / "source.zip"
        _regular(source_zip, MAX_SOURCE_ZIP)
        if hash_file(source_zip, maximum=MAX_SOURCE_ZIP) != source_hash:
            raise BundleError("source_hash")
        _regular(root / "RELEASE_NOTES.md", 32 * 1024)
        notes_bytes = (root / "RELEASE_NOTES.md").read_bytes()
        if core._PRIVATE_KEY.search(notes_bytes):
            raise BundleError("private_material")
        notes = notes_bytes.decode("utf-8")
        source_files = manifest.get("files")
        if not isinstance(source_files, dict) or not 1 <= len(source_files) <= 5000:
            raise BundleError("source_files")
        for name, expected in source_files.items():
            _source_name(name, version=version)
            if not isinstance(expected, str) or _HASH.fullmatch(expected) is None:
                raise BundleError("source_files")
        with zipfile.ZipFile(source_zip) as archive:
            entries = archive.infolist()
            if (len(entries) != len(source_files) or len({x.filename.casefold() for x in entries}) != len(entries)
                    or {x.filename for x in entries} != set(source_files)
                    or sum(x.file_size for x in entries) > MAX_SOURCE_BYTES):
                raise BundleError("source_archive")
            special = {}
            for entry in entries:
                _source_name(entry.filename, version=version)
                if (entry.is_dir() or entry.flag_bits & 1 or entry.file_size > MAX_SOURCE_FILE
                        or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)):
                    raise BundleError("source_archive")
                digest, count = hashlib.sha256(), 0
                chunks = [] if entry.filename in (set(core.HELPER_FILES) | {
                    "proxy/__init__.py", "CHANGELOG.md", "docs/RELEASE_NOTES.md"}) else None
                with archive.open(entry) as source:
                    while chunk := source.read(256 * 1024):
                        count += len(chunk)
                        if count > MAX_SOURCE_FILE:
                            raise BundleError("source_archive")
                        digest.update(chunk)
                        if chunks is not None:
                            chunks.append(chunk)
                if count != entry.file_size or digest.hexdigest() != source_files[entry.filename]:
                    raise BundleError("source_file_hash")
                if chunks is not None:
                    special[entry.filename] = b"".join(chunks)
            if (_source_version(special.get("proxy/__init__.py", b"")) != version
                    or special.get("CHANGELOG.md") != assets["CHANGELOG.md"].read_bytes()
                    or special.get("docs/RELEASE_NOTES.md") != notes_bytes):
                raise BundleError("source_asset_mismatch")
            with zipfile.ZipFile(assets["TgWsProxy_helper.zip"]) as helper:
                helper_files = {name.removeprefix("TgWsProxy-helper/") for name in helper.namelist()}
                if any(name not in special or helper.read("TgWsProxy-helper/" + name)
                       != special[name].replace(b"\r\n", b"\n") for name in helper_files):
                    raise BundleError("helper_source_mismatch")
        identity = {"version": version, "build_commit": manifest["build_commit"],
                    "source_commit": manifest["source_commit"], "source_zip_sha256": source_hash,
                    "assets": hashes, "notes_sha256": hashlib.sha256(notes_bytes).hexdigest(),
                    "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest()}
        bundle_id = hashlib.sha256(b"TGPROXY_RELEASE_BUNDLE\0" + canonical_json(identity)).hexdigest()
        return ReleaseBundle(root, version, assets, notes, source_zip, manifest["source_commit"],
                             manifest["build_commit"], manifest, bundle_id,
                             asset_sizes=asset_sizes, manifest_sha256=identity["manifest_sha256"])
    except BundleError:
        raise
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, zipfile.BadZipFile):
        raise BundleError("bundle") from None


def revalidate_bundle(bundle: ReleaseBundle) -> ReleaseBundle:
    if not isinstance(bundle, ReleaseBundle):
        raise BundleError("bundle_type")
    current = load_bundle(bundle.root)
    if current.bundle_id != bundle.bundle_id:
        raise BundleError("bundle_changed")
    return current
