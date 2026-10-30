"""Prepare the APK's exact public Helper sources, never configs, credentials or build environments."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import uuid


ANDROID = Path(__file__).resolve().parents[1]
POLICY = ANDROID / "app/src/main/java/io/github/byshadow64/tgproxy/HelperPayloadAssets.kt"


def allowed_paths() -> tuple[str, ...]:
    text = POLICY.read_text(encoding="utf-8")
    block = text.split("// BEGIN_HELPER_ALLOWLIST", 1)[1].split("// END_HELPER_ALLOWLIST", 1)[0]
    paths = tuple(re.findall(r'"([A-Za-z0-9_./-]+)"', block))
    if len(paths) != 27 or len(set(paths)) != len(paths):
        raise ValueError("Invalid compiled Helper allowlist")
    return paths


def source_allowlist(source: Path) -> tuple[str, ...]:
    module = ast.parse((source / "utils/helper_payload.py").read_text(encoding="utf-8-sig"))
    assignments = [node for node in module.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "HELPER_PAYLOAD_FILES" for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError("Missing authoritative Helper allowlist")
    return tuple(ast.literal_eval(assignments[0].value))


def prepare(source_root: Path, output: Path) -> dict:
    source_root = source_root.resolve(strict=True)
    output = output.resolve()
    paths = allowed_paths()
    if set(source_allowlist(source_root)) != set(paths):
        raise ValueError("Desktop and Android public Helper allowlists differ")
    values = {}
    for relative in paths:
        path = source_root / relative
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(source_root):
            raise ValueError("Helper source is not a contained regular file")
        data = path.read_bytes().replace(b"\r\n", b"\n")
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("Helper source exceeds bound")
        values[relative] = data
    if sum(map(len, values.values())) > 16 * 1024 * 1024:
        raise ValueError("Helper payload exceeds bound")
    manifest = {"v": 1, "files": [{"path": path, "size": len(values[path]), "sha256": hashlib.sha256(values[path]).hexdigest()}
                                  for path in sorted(values)]}
    values["manifest.json"] = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    if output.exists():
        for item in output.rglob("*"):
            if item.is_symlink() or not item.resolve().is_relative_to(output):
                raise ValueError("Unsafe output entry")
            if item.is_file() and item.relative_to(output).as_posix() not in values:
                raise ValueError("Unexpected existing output file; use a clean explicit output folder")
    output.mkdir(parents=True, exist_ok=True)
    for name, data in values.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
        with temp.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    return {"source_root": str(source_root), "output": str(output), "files": manifest["files"],
            "manifest_sha256": hashlib.sha256(values["manifest.json"]).hexdigest(), "public_sources_only": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=ANDROID / "app/src/main/assets/helper-payload")
    args = parser.parse_args()
    print(json.dumps(prepare(args.source_root, args.output), ensure_ascii=False, indent=2))
