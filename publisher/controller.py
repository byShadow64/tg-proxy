"""One bounded worker at a time; workers never access Tk widgets."""
from __future__ import annotations

import queue
import threading


SAFE_CODES = frozenset({
    "approval", "approval_file", "approval_format", "approval_identity", "approval_key",
    "approval_missing", "approval_required", "approval_signature", "approval_signing_failed",
    "approved_commit_not_in_default_branch", "asset_allowlist", "asset_conflict", "asset_file",
    "asset_hash", "asset_manifest_mismatch", "authentication", "authentication_required",
    "bundle", "bundle_archive", "bundle_changed", "bundle_invalid", "bundle_too_large",
    "bundle_type", "bundle_required", "busy", "cancelled", "checksums", "choose_one_ssh_authentication", "commit",
    "conflict", "connect", "connection", "credentials", "directory_type", "downgrade",
    "draft_input_conflict", "draft_input_hash", "draft_input_required", "dispatch_unconfirmed", "duplicate_json",
    "endpoint", "expiry", "export", "export_target", "file_size", "file_type", "forbidden",
    "helper_archive", "helper_source_mismatch", "history_store", "host_key", "host_key_mismatch",
    "http_error", "https", "immutable_version", "incomplete_assets", "install",
    "invalid_default_branch", "invalid_repository", "invalid_response", "invalid_tag",
    "invalid_token", "invalid_workflow_input", "json_number", "key_file", "key_id",
    "key_inside_checkout", "latest_downgrade", "latest_not_confirmed", "layout", "legacy_profile",
    "manifest", "manifest_fields", "manifest_readback", "manifest_size", "missing_file",
    "network_error", "not_approved_stable", "not_found", "notes", "operation_failed", "options",
    "output_exists", "output_limit", "pagination_limit", "payload", "pe_version", "permission",
    "permission_or_rate_limit", "private_material", "private_or_test_source", "profile",
    "profile_store", "public_active_repository_required", "public_verification", "publication_unconfirmed",
    "published_release_incomplete", "rate_limit", "rate_limited", "release_conflict", "release_notes_conflict",
    "release_workflow_running", "remote_directory", "remote_file", "remote_hash",
    "repository_mismatch", "response_too_large", "result", "root_required", "secret_store",
    "sftp", "signature", "signing_key", "source_archive", "source_asset_mismatch",
    "source_file_hash", "source_files", "source_hash", "source_path", "source_version",
    "ssh_options", "stable_version", "stable_version_required", "store_inside_project",
    "successful_trusted_ci_required", "tag_conflict", "tag_missing", "timeout", "timestamp",
    "token", "trusted_actions_context_required", "trusted_workflow_not_deployed", "unauthorized",
    "unexpected_bundle_file", "unsafe_redirect", "unsafe_url", "unsupported_system", "url",
    "version", "webroot", "write_access_required",
})
SAFE_PHASES = frozenset({
    "approval", "checking_https", "complete", "connect", "connecting", "creating_draft",
    "creating_input_draft", "dispatch", "github", "github_upload", "loading", "operation",
    "preflight", "preflight_complete", "public_verification", "published", "publishing",
    "rate_limit", "readback", "server", "upload", "uploading", "validating", "verify",
    "verifying", "verifying_public", "waiting", "workflow_dispatched",
})
SAFE_CHANNELS = frozenset({"server", "github", "bundle"})


def protocol_code(value) -> str:
    return value if isinstance(value, str) and value in SAFE_CODES else "operation_failed"


def safe_code(error) -> str:
    try:
        return protocol_code(getattr(error, "code", "operation_failed"))
    except Exception:
        return "operation_failed"


class JobRunner:
    def __init__(self):
        self.events = queue.Queue(maxsize=256)
        self.cancel = threading.Event()
        self._thread = None
        self._active = False
        self._closed = False
        self._closing = False
        self._generation = 0
        self._event_lock = threading.Lock()

    @property
    def busy(self):
        return self._active

    def _put(self, item, *, final=False):
        # Progress callbacks may arrive concurrently. Eviction and the final
        # enqueue must be indivisible, otherwise a late callback can steal the
        # only free slot and leave the UI waiting forever for completion.
        with self._event_lock:
            if self._closed:
                return
            try:
                self.events.put_nowait(item)
            except queue.Full:
                if final:
                    try:
                        self.events.get_nowait()
                    except queue.Empty:
                        pass
                    self.events.put_nowait(item)

    def start(self, function):
        if self._active or self._closed or self._closing:
            return False
        self._active = True
        self._generation += 1
        self.cancel = threading.Event()
        generation, cancel = self._generation, self.cancel

        def emit(event):
            if not isinstance(event, dict):
                return
            clean = {}
            if "phase" in event:
                value = event["phase"]
                clean["phase"] = value if isinstance(value, str) and value in SAFE_PHASES else "operation"
            if "code" in event:
                clean["code"] = protocol_code(event["code"])
            if isinstance(event.get("channel"), str) and event["channel"] in SAFE_CHANNELS:
                clean["channel"] = event["channel"]
            for key in ("bytes", "total", "done", "wait_seconds"):
                value = event.get(key)
                if type(value) in (int, float) and 0 <= value <= 10**12:
                    clean[key] = value
            self._put({"kind": "progress", "generation": generation, "event": clean})

        def work():
            try:
                value = function(emit, cancel)
                result = {"kind": "complete", "value": value}
            except Exception as error:
                try:
                    committed = getattr(error, "committed", False) is True
                except Exception:
                    committed = False
                result = {"kind": "error", "code": safe_code(error),
                          "committed": committed}
                try:
                    retry = getattr(error, "retry_after", None)
                    if type(retry) in (int, float) and 0 < retry <= 86400:
                        result["retry_after"] = min(86400, int(retry) + 1)
                except Exception:
                    pass
            self._put({**result, "generation": generation}, final=True)

        try:
            self._thread = threading.Thread(target=work, name="publisher-operation", daemon=True)
            self._thread.start()
        except Exception:
            # Resource exhaustion can prevent construction/start before work()
            # owns cleanup. Deliver the usual safe final event so the UI can
            # unlock its controls; never retain an unstarted thread to join.
            self._thread = None
            self._put({"kind": "error", "generation": generation,
                       "code": "operation_failed", "committed": False}, final=True)
        return True

    def request_cancel(self):
        self.cancel.set()

    def poll(self):
        result = []
        while True:
            try:
                item = self.events.get_nowait()
            except queue.Empty:
                return result
            if item["generation"] != self._generation or self._closed:
                continue
            if item["kind"] in {"complete", "error"}:
                # The final event is published after the operation's finally/
                # cleanup. No new operation is permitted until it is consumed.
                self._active = False
            result.append(item)

    def close(self):
        self._closing = True
        self.request_cancel()
        if self._thread is not None and self._thread.is_alive():
            return False
        self._closed = True
        self._active = False
        return True
