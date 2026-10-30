"""A small source-only helper payload, shared by source and frozen clients."""
from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path
from typing import Optional


HELPER_PAYLOAD_FILES = (
    "helper_server.py", "helper_pairing.py", "deploy_helper.sh", "tg-helper.service", "LICENSE",
    "proxy/__init__.py", "proxy/config.py", "proxy/balancer.py",
    "proxy/utils.py", "proxy/http_transport.py", "proxy/route_policy.py", "proxy/project.py",
    "helper_registry.py", "helper_registry_agent.py", "helper_enrollment.py", "deploy_helper_registry.sh",
    "proxy/registry_protocol.py", "proxy/registry_helper.py",
    "helper_requirements.txt", "helper_registry_requirements.txt", "helper_certbot_requirements.txt",
    "tg-helper-registry-agent.service", "tg-helper-registry-agent.timer", "tg-helper-enroll.service",
    "tg-helper-certbot-renew.service", "tg-helper-certbot-renew.timer", "helper_registry_renew.sh",
)
PAYLOAD_RESOURCE = "helper_payload.tar"
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024


def _validate_payload(payload: bytes) -> bytes:
    if not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("Invalid helper payload size")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) != len(HELPER_PAYLOAD_FILES):
            raise ValueError("Invalid helper payload file set")
        if {member.name for member in members} != set(HELPER_PAYLOAD_FILES):
            raise ValueError("Invalid helper payload file set")
        if any(not member.isfile() or member.size > MAX_PAYLOAD_BYTES for member in members):
            raise ValueError("Helper payload must contain only regular source files")
    return payload


def build_helper_payload(root: Optional[Path] = None) -> bytes:
    """Return a deterministic TAR with exactly the reviewed helper allowlist.

    Frozen applications read their build-time resource, never the surrounding
    user's project, config or Git history. An explicit root is for builders.
    """
    if root is None and getattr(sys, "frozen", False):
        bundle_path = getattr(sys, "_MEIPASS", None)
        if not bundle_path:
            raise RuntimeError("The bundled helper payload is unavailable")
        bundle = Path(bundle_path)
        return _validate_payload((bundle / PAYLOAD_RESOURCE).read_bytes())
    source_root = (Path(root) if root is not None else Path(__file__).resolve().parents[1]).resolve()
    if root is None and not (source_root / "deploy_helper.sh").is_file():
        source_root = source_root / "helper_payload_src"
    contents = []
    for relative in HELPER_PAYLOAD_FILES:
        source = source_root / relative
        if source.is_symlink() or not source.is_file():
            raise ValueError("Helper payload source is missing or is not a regular file")
        try:
            source.resolve().relative_to(source_root)
        except ValueError as exc:
            raise ValueError("Helper payload source escaped its root") from exc
        data = source.read_bytes().replace(b"\r\n", b"\n")
        contents.append((relative, data))
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for relative, data in contents:
            member = tarfile.TarInfo(relative)
            member.size = len(data)
            member.mode = 0o755 if relative.endswith(".sh") else 0o644
            member.mtime = member.uid = member.gid = 0
            archive.addfile(member, io.BytesIO(data))
    return _validate_payload(stream.getvalue())
