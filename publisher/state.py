"""Public, per-bundle/per-target receipts. Never store credentials or raw errors."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from publisher.controller import SAFE_CODES, protocol_code
from publisher.profiles import data_directory


MAX_HISTORY_BYTES = 2 * 1024 * 1024
ASSET_NAMES = frozenset({"CHANGELOG.md", "SHA256SUMS.txt", "TgWsProxy_helper.zip", "TgWsProxy_windows.exe"})
SAFE_STATUSES = frozenset({
    "published", "published_and_verified", "already_published", "queued", "draft", "draft_ready",
    "draft_input_ready", "workflow_dispatched", "dispatch_unconfirmed", "not_published", "pending", "verification_pending",
    "published_verification_pending", "publication_unconfirmed", "different_version", "failed", "cancelled", "ready", "verified",
})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
_URL_FIELDS = frozenset({"release_url", "manifest_url", "workflow_url"})
_RECEIPT_FIELDS = frozenset({"bundle_id", "version", "channel", "updated_at", "source_commit",
                             "assets", "status", "code", "verified", "committed"}) | _URL_FIELDS


def _public_url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return False
    try:
        from utils.update_manifest import validate_https_url
        validate_https_url(value)
        parsed = urlsplit(value)
        return not (parsed.query or parsed.fragment or parsed.username or parsed.password)
    except (ValueError, TypeError):
        return False


def _identity(bundle_id, version, source_commit, assets):
    return (isinstance(bundle_id, str) and _HASH.fullmatch(bundle_id) is not None
            and isinstance(version, str) and _VERSION.fullmatch(version) is not None
            and isinstance(source_commit, str) and _COMMIT.fullmatch(source_commit) is not None
            and isinstance(assets, dict) and set(assets) == ASSET_NAMES
            and all(isinstance(value, str) and _HASH.fullmatch(value) is not None
                    for value in assets.values()))


def _valid_receipt(value):
    if (not isinstance(value, dict) or set(value) - _RECEIPT_FIELDS
            or not _identity(value.get("bundle_id"), value.get("version"),
                             value.get("source_commit"), value.get("assets"))
            or value.get("channel") not in {"github", "server"}
            or value.get("status") not in SAFE_STATUSES
            or type(value.get("verified")) is not bool
            or type(value.get("committed")) is not bool):
        return False
    stamp = value.get("updated_at")
    if not isinstance(stamp, str) or len(stamp) > 64:
        return False
    try:
        if datetime.fromisoformat(stamp).tzinfo is None:
            return False
    except ValueError:
        return False
    if "code" in value and (not isinstance(value["code"], str) or value["code"] not in SAFE_CODES):
        return False
    return all(field not in value or _public_url(value[field]) for field in _URL_FIELDS)


class StateError(RuntimeError):
    code = "history_store"


class PublicationState:
    def __init__(self, path=None):
        self.path = Path(path) if path else data_directory() / "publication-history.json"

    @staticmethod
    def key(bundle_id, channel, target):
        return hashlib.sha256((bundle_id + "\0" + channel + "\0" + target).encode("utf-8")).hexdigest()

    def load(self):
        if not self.path.exists():
            return {}
        try:
            meta = self.path.lstat()
            if (self.path.is_symlink() or getattr(self.path, "is_junction", lambda: False)()
                    or not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_HISTORY_BYTES):
                raise ValueError
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if (not isinstance(value, dict) or set(value) != {"schema", "receipts"}
                    or type(value.get("schema")) is not int or value["schema"] != 1
                    or not isinstance(value.get("receipts"), dict) or len(value["receipts"]) > 500
                    or any(not isinstance(k, str) or _HASH.fullmatch(k) is None or not _valid_receipt(v)
                           for k, v in value["receipts"].items())):
                raise ValueError
            return value["receipts"]
        except Exception:
            raise StateError("Publication history is unavailable") from None

    def record(self, bundle, channel, target, result):
        if (channel not in {"github", "server"} or not isinstance(target, str)
                or not 1 <= len(target) <= 1024 or any(ord(c) < 32 for c in target)
                or not isinstance(result, dict)):
            raise StateError("Invalid publication receipt")
        try:
            assets = dict(bundle.manifest["assets"])
            if not _identity(bundle.bundle_id, bundle.version, bundle.source_commit, assets):
                raise ValueError
        except Exception:
            raise StateError("Invalid publication receipt") from None
        receipt = {"bundle_id": bundle.bundle_id, "version": bundle.version, "channel": channel,
                   "updated_at": datetime.now(timezone.utc).isoformat(),
                   "source_commit": bundle.source_commit,
                   "assets": assets}
        # Explicitly whitelist protocol codes and public receipt URLs. The UI
        # and network exception text can never become receipt fields.
        status = result.get("status")
        receipt["status"] = status if isinstance(status, str) and status in SAFE_STATUSES else "failed"
        if "code" in result:
            receipt["code"] = protocol_code(result["code"])
        for field in _URL_FIELDS:
            value = result.get(field)
            if _public_url(value):
                receipt[field] = value
        receipt["verified"] = (result.get("verified") is True or result.get("public_verified") is True) and receipt["status"] in {"published", "published_and_verified", "already_published", "verified"}
        receipt["committed"] = result.get("committed") is True
        receipts = self.load()
        receipts[self.key(bundle.bundle_id, channel, target)] = receipt
        # A bounded history is a local convenience; remote revalidation always
        # happens again before publication, even if a receipt says success.
        receipts = dict(sorted(receipts.items(), key=lambda pair: pair[1].get("updated_at", ""))[-500:])
        temporary = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.is_symlink():
                raise ValueError
            data = json.dumps({"schema": 1, "receipts": receipts}, ensure_ascii=False, indent=2)
            while len(data.encode("utf-8")) > MAX_HISTORY_BYTES and len(receipts) > 1:
                receipts.pop(next(iter(receipts)))
                data = json.dumps({"schema": 1, "receipts": receipts}, ensure_ascii=False, indent=2)
            if len(data.encode("utf-8")) > MAX_HISTORY_BYTES:
                raise ValueError
            temporary = self.path.with_name(".history-" + secrets.token_hex(12) + ".tmp")
            with temporary.open("x", encoding="utf-8") as stream:
                stream.write(data)
            os.replace(temporary, self.path)
        except Exception:
            raise StateError("Publication history could not be saved") from None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return receipt
