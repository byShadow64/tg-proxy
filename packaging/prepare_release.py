"""Prepare only public binaries and whitelisted helper sources for a release."""
from __future__ import annotations

import argparse
import hashlib
import io
import shutil
import zipfile
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER_FILES = (
    "helper_server.py", "helper_pairing.py", "deploy_helper.sh", "tg-helper.service", "LICENSE",
    "proxy/__init__.py", "proxy/project.py", "proxy/config.py",
    "proxy/balancer.py", "proxy/utils.py", "proxy/http_transport.py", "proxy/route_policy.py", "docs/RU/Helper.md",
    "helper_registry.py", "helper_registry_agent.py", "helper_enrollment.py", "deploy_helper_registry.sh",
    "proxy/registry_protocol.py", "proxy/registry_helper.py",
    "helper_requirements.txt", "helper_registry_requirements.txt", "helper_certbot_requirements.txt",
    "tg-helper-registry-agent.service", "tg-helper-registry-agent.timer", "tg-helper-enroll.service",
    "tg-helper-certbot-renew.service", "tg-helper-certbot-renew.timer", "helper_registry_renew.sh",
)


def prepare(executable: Path, output: Path):
    if executable.is_symlink() or not executable.is_file() or executable.stat().st_size > 256 * 1024 * 1024:
        raise FileNotFoundError(executable)
    output.mkdir(parents=True, exist_ok=True)
    windows = output / "TgWsProxy_windows.exe"
    helper = output / "TgWsProxy_helper.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in HELPER_FILES:
            source = ROOT / relative
            info = zipfile.ZipInfo(f"TgWsProxy-helper/{relative}")
            info.create_system = 3
            mode = 0o755 if relative.endswith(".sh") else 0o644
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, source.read_bytes().replace(b"\r\n", b"\n"))
    checksums = output / "SHA256SUMS.txt"
    changelog = output / "CHANGELOG.md"
    contents = {windows: executable.read_bytes(), helper: buffer.getvalue(),
                changelog: (ROOT / "CHANGELOG.md").read_bytes()}
    contents[checksums] = "".join(
        f"{hashlib.sha256(contents[path]).hexdigest()}  {path.name}\n" for path in (windows, helper)
    ).encode("ascii")
    # Idempotent exact reuse is allowed; different bytes require another output
    # directory. Validate all destinations before creating any of them.
    for path, data in contents.items():
        if path.exists() and (path.is_symlink() or not path.is_file() or path.read_bytes() != data):
            raise FileExistsError("Prepared release files cannot be overwritten")
    for path, data in contents.items():
        if not path.exists():
            with path.open("xb") as target:
                target.write(data)
    return windows, helper, checksums, changelog


def create_bundle(executable: Path, output: Path, *, build_commit=None):
    """Prepare an immutable data folder from a built EXE, without building it.

    CI success or an explicit operator approval must still sign this bundle
    before publication. A manifest boolean alone is never publishing authority.
    """
    sys.path.insert(0, str(ROOT))
    from publisher.bundle import load_bundle, _source_name
    from proxy import __version__
    if (not isinstance(__version__, str)
            or re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", __version__) is None):
        raise ValueError("Only a stable version may be prepared")
    branch = subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip()
    if branch.casefold() == "staging":
        raise ValueError("Staging is local only")
    # The source commit must describe all tracked bytes used for this package.
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT):
        raise ValueError("Commit tracked source changes before preparing a bundle")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    build_commit = build_commit or commit
    if re.fullmatch(r"[0-9a-f]{40}", build_commit) is None:
        raise ValueError("A full build commit SHA is required")
    output = output.resolve()
    if output.exists():
        raise FileExistsError("A bundle is immutable; choose a new directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    paths = [p for p in subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0") if p]
    if not paths:
        raise ValueError("The source snapshot is empty")
    for path in paths:
        _source_name(path, version=__version__)
    with tempfile.TemporaryDirectory(prefix=".tgproxy-bundle-", dir=output.parent) as temporary:
        stage = Path(temporary)
        prepare(executable.resolve(strict=True), stage / "assets")
        shutil.copy2(ROOT / "docs/RELEASE_NOTES.md", stage / "RELEASE_NOTES.md")
        files = {}
        with zipfile.ZipFile(stage / "source.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(paths):
                source = ROOT / name
                if source.is_symlink() or not source.is_file():
                    raise ValueError("Snapshot source must be an ordinary file")
                data = source.read_bytes()
                files[name] = hashlib.sha256(data).hexdigest()
                archive.writestr(name, data)
        manifest = {"schema": 1, "version": __version__, "created_at": datetime.now(timezone.utc).isoformat(),
                    "source_commit": commit, "build_commit": build_commit, "files": files,
                    "source_zip_sha256": hashlib.sha256((stage / "source.zip").read_bytes()).hexdigest(),
                    "assets": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (stage / "assets").iterdir()},
                    "release_ready": True}
        (stage / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        load_bundle(stage)
        # Create only this new folder; rename its known children without ever
        # replacing an existing bundle or an existing asset.
        output.mkdir(exist_ok=False)
        for child in stage.iterdir():
            child.rename(output / child.name)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=ROOT / "dist" / "TgWsProxy.exe")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "release")
    parser.add_argument("--bundle-output", type=Path, help="New immutable publication folder; does not rebuild the EXE")
    parser.add_argument("--build-commit", help="Full source commit that produced the supplied EXE")
    args = parser.parse_args()
    if args.bundle_output:
        print(create_bundle(args.exe, args.bundle_output, build_commit=args.build_commit))
    else:
        for path in prepare(args.exe.resolve(), args.output.resolve()):
            print(path)


if __name__ == "__main__":
    main()
