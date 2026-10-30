"""Promote an approved data-only bundle from a trusted manual Actions run.

This command never builds or imports the downloaded project. Authentication is
read only from GH_TOKEN; no token, response headers, or raw errors are printed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from publisher.github import (  # noqa: E402
    create_missing_tag_for_actions,
    download_draft_bundle,
    publish_github,
    trusted_actions_client,
    verify_workflow_bundle,
)


_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")
_TAG = re.compile(r"v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ERROR_CODES = frozenset({
    "arguments", "invalid_token", "authentication_required", "permission_or_rate_limit",
    "write_access_required", "rate_limited", "not_found", "conflict", "http_error",
    "cancelled", "timeout", "network_error", "unsafe_url", "unsafe_redirect",
    "response_too_large", "invalid_response", "invalid_repository", "repository_mismatch",
    "public_active_repository_required", "invalid_default_branch", "stable_version_required",
    "trusted_actions_context_required", "invalid_workflow_input", "draft_input_required",
    "draft_input_conflict", "draft_input_hash", "bundle_too_large", "bundle_archive",
    "output_exists", "isolated_output_required", "tag_mismatch", "tag_conflict", "tag_missing",
    "approved_commit_not_in_default_branch", "successful_trusted_ci_required",
    "release_workflow_running", "latest_downgrade", "latest_not_confirmed",
    "release_conflict", "release_notes_conflict", "asset_conflict", "incomplete_assets", "published_release_incomplete",
    "bundle_changed", "bundle_invalid", "approval_required", "approval_file", "approval_format",
    "approval_key", "approval_identity", "approval_signature", "pagination_limit",
    "verification_unconfirmed", "publication_unconfirmed", "publisher_failure",
})


class PromotionError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__("Release promotion failed")


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes unrecognised arguments, which may include a
        # token mistakenly passed on the command line. Keep failures generic.
        raise PromotionError("arguments")


def _positive_integer(value):
    try:
        number = int(value)
        if number <= 0:
            raise ValueError
        return number
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("positive integer required") from None


def _parser():
    parser = _Parser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--draft-release-id", type=_positive_integer, required=True)
    parser.add_argument("--bundle-asset-id", type=_positive_integer, required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="New isolated directory inside RUNNER_TEMP")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify-only", action="store_true")
    mode.add_argument("--publish", action="store_true")
    parser.add_argument("--create-missing-tag", action="store_true")
    return parser


def _isolated_output(output):
    """Refuse existing paths and anything outside the runner's temporary root."""
    try:
        raw_root = os.environ.get("RUNNER_TEMP", "")
        if not raw_root:
            raise PromotionError("isolated_output_required")
        runner_root = Path(raw_root).resolve(strict=True)
        if not runner_root.is_dir():
            raise PromotionError("isolated_output_required")
        raw_output = Path(output).absolute()
        path = raw_output.resolve()
        if path == runner_root or not path.is_relative_to(runner_root):
            raise PromotionError("isolated_output_required")
        # Existing symlink/junction ancestors could redirect a later write even
        # when the leaf directory itself does not exist yet.
        ancestor = raw_output
        while ancestor != ancestor.parent:
            if ancestor.is_symlink() or getattr(ancestor, "is_junction", lambda: False)():
                raise PromotionError("isolated_output_required")
            if ancestor.resolve() == runner_root:
                break
            ancestor = ancestor.parent
        if path.exists():
            raise PromotionError("output_exists")
        archive = path.parent / (path.name + ".input.zip")
        if archive.exists() or archive.is_symlink():
            raise PromotionError("output_exists")
        return path
    except PromotionError:
        raise
    except (OSError, ValueError, RuntimeError):
        raise PromotionError("isolated_output_required") from None


def _validate_inputs(args):
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise PromotionError("authentication_required")
    if (len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token)):
        raise PromotionError("invalid_token")
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"):
        raise PromotionError("trusted_actions_context_required")
    if (_REPOSITORY.fullmatch(args.repository) is None
            or args.repository.endswith(("/.", "/.."))
            or _TAG.fullmatch(args.tag) is None
            or _DIGEST.fullmatch(args.bundle_sha256) is None
            or (args.create_missing_tag and not args.publish)):
        raise PromotionError("arguments")
    return token, _isolated_output(args.output)


def _safe_failure(exc):
    try:
        code = getattr(exc, "code", "publisher_failure")
        if code not in _SAFE_ERROR_CODES:
            code = "publisher_failure"
        result = {"status": "failed", "code": code}
        http_status = getattr(exc, "http_status", None)
        if type(http_status) is int and 100 <= http_status <= 599:
            result["http_status"] = http_status
        retry = getattr(exc, "retry_after", None)
        if type(retry) in (int, float) and 0 < retry <= 86400:
            result["retry_after"] = retry
        return result
    except Exception:
        return {"status": "failed", "code": "publisher_failure"}


def main(argv=None):
    try:
        args = _parser().parse_args(argv)
        token, output = _validate_inputs(args)
        client = trusted_actions_client(args.repository, token)
        bundle = download_draft_bundle(
            args.repository, token, args.draft_release_id, args.bundle_asset_id,
            args.bundle_sha256, output, _client=client,
        )
        if args.tag != "v" + bundle.version:
            raise PromotionError("tag_mismatch")
        facts = verify_workflow_bundle(bundle, args.repository, token, _client=client)
        if (not isinstance(facts, dict) or facts.get("status") != "verified"
                or facts.get("approval_verified") is not True
                or facts.get("ci_verified") is not True
                or facts.get("tag") != args.tag
                or facts.get("source_commit") != bundle.source_commit
                or facts.get("bundle_id") != bundle.bundle_id):
            raise PromotionError("verification_unconfirmed")
        result = {"status": "verified", "version": bundle.version, "tag": args.tag,
                  "source_commit": bundle.source_commit, "bundle_id": bundle.bundle_id,
                  "verified": True, "published": False}
        if args.publish:
            if args.create_missing_tag:
                create_missing_tag_for_actions(bundle, args.repository, token, _client=client)
            elif facts.get("tag_missing") is True:
                raise PromotionError("tag_missing")
            report = publish_github(bundle, args.repository, token, require_ci=True,
                                    _client=client)
            if (not isinstance(report, dict) or report.get("verified") is not True
                    or report.get("status") not in {"published", "already_published"}
                    or report.get("tag") != args.tag):
                raise PromotionError("publication_unconfirmed")
            result.update(status=report["status"], published=True,
                          release_url=f"https://github.com/{args.repository}/releases/tag/{args.tag}")
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"status": "failed", "code": "cancelled"}))
        return 1
    except Exception as exc:
        print(json.dumps(_safe_failure(exc), ensure_ascii=True, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
