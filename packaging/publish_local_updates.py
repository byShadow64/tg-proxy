"""Promote one approved immutable bundle; never read notes from the checkout."""
from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main(argv=None):
    from publisher.bundle import load_bundle
    from publisher.profiles import ServerCredentials, default_keys_path, load_default_profile
    from publisher.server import check_server, publish_bundle
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, help="Verified immutable publication folder")
    parser.add_argument("--keys", type=Path, default=default_keys_path())
    parser.add_argument("--check-connection", action="store_true")
    parser.add_argument("--candidate", action="store_true")
    parser.add_argument("--json-progress", action="store_true")
    args = parser.parse_args(argv)
    if not args.bundle and not args.check_connection:
        parser.error("--bundle is required; current working-tree binaries/notes are not publication inputs")
    try:
        profile = load_default_profile(args.keys)
        if args.candidate:
            profile = replace(profile, profile_id="candidate", name="Candidate",
                              webroot=profile.webroot.rstrip("/") + "/candidate",
                              base_url=profile.base_url.rstrip("/") + "/candidate")
        credentials = ServerCredentials(legacy_key_path=str(args.keys))
        emit = (lambda event: print(json.dumps(event), file=sys.stderr, flush=True)) if args.json_progress else None
        if args.check_connection:
            result = check_server(profile, credentials, emit=emit)
        else:
            result = publish_bundle(load_bundle(args.bundle), profile, credentials, emit=emit)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"error": "cancelled"}), file=sys.stderr)
        return 130
    except Exception as error:
        code = getattr(error, "code", "publication")
        code = code if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,64}", code) else "publication"
        print(json.dumps({"error": code, "committed": bool(getattr(error, "committed", False))}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
