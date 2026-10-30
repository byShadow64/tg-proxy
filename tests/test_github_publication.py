"""Real local HTTP responses exercise publication without contacting GitHub."""
from __future__ import annotations

import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from release_tools import github, trust
from tests.release_fixtures import sign_test_approval


REPO = "example-owner/tg-proxy"
COMMIT = "a" * 40
TOKEN = "SYNTHETIC-TEST-TOKEN-DO-NOT-LOG"


class FakeAPI(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status, data=None, headers=None, binary=False):
        raw = data if binary else json.dumps(data).encode()
        raw = raw or b""
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            if status == 403 and self.server.split_failure:
                self.wfile.write(raw[:5])
                self.wfile.flush()
                time.sleep(.02)
                self.wfile.write(raw[5:])
            else:
                self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def request_record(self):
        self.server.requests.append((self.command, self.path, self.headers.get("Authorization")))

    def asset_meta(self, value):
        return {key: item for key, item in value.items() if key != "data"}

    def do_GET(self):
        self.request_record()
        path = urlsplit(self.path).path
        prefix = "/repos/" + REPO
        if self.server.failure:
            status, headers = self.server.failure
            return self.send(status, {"message": self.server.failure_message}, headers)
        if path == "/user":
            return self.send(200, {"login": "byShadow64"})
        if path == prefix:
            return self.send(200, {"full_name": REPO, "private": False, "archived": False, "default_branch": "main", "permissions": {"push": True}})
        if path == prefix + "/git/ref/tags/v1.14.9":
            return self.send(200, {"object": {"type": "commit", "sha": self.server.tag_commit}}) if self.server.tag_commit else self.send(404, {})
        if "/compare/" in path:
            return self.send(200, {"status": self.server.compare_status})
        if path == prefix + "/actions/runs":
            runs = [{"id": 1, "path": ".github/workflows/windows-ci.yml", "status": "completed", "conclusion": self.server.ci_status, "event": "push", "head_repository": {"full_name": REPO}}]
            return self.send(200, {"workflow_runs": runs})
        if path == prefix + "/actions/workflows/build.yml/runs":
            status = parse_qs(urlsplit(self.path).query).get("status", [None])[0]
            return self.send(200, {"workflow_runs": [run for run in self.server.active_runs if not run.get("status") or run["status"] == status]})
        if path == prefix + "/actions/runs/99":
            return self.send(200, {"id": 99, "path": ".github/workflows/build.yml", "event": "workflow_dispatch", "head_sha": COMMIT, "head_branch": "main", "head_repository": {"full_name": REPO}})
        if path == prefix + "/releases/latest":
            latest = self.server.latest
            return self.send(200, latest) if latest else self.send(404, {})
        if path == prefix + "/releases":
            return self.send(200, list(self.server.releases.values()))
        if "/releases/tags/" in path:
            tag = path.rsplit("/", 1)[1]
            item = next((r for r in self.server.releases.values() if r["tag_name"] == tag), None)
            if item and item.get("draft") and self.server.hide_drafts:
                item = None
            return self.send(200, item) if item else self.send(404, {})
        if "/releases/assets/" in path:
            asset_id = int(path.rsplit("/", 1)[1])
            asset = next((a for values in self.server.assets.values() for a in values.values() if a["id"] == asset_id), None)
            if self.server.redirect:
                return self.send(302, {}, {"Location": self.server.redirect})
            return self.send(200, asset["data"], binary=True) if asset else self.send(404, {})
        if path == "/cdn-asset":
            return self.send(200, self.server.cdn_data, binary=True)
        if path.endswith("/assets"):
            release_id = int(path.split("/")[-2])
            return self.send(200, [self.asset_meta(a) for a in self.server.assets[release_id].values()])
        if "/releases/" in path:
            return self.send(200, self.server.releases[int(path.rsplit("/", 1)[1])])
        return self.send(404, {})

    def do_POST(self):
        self.request_record()
        path = urlsplit(self.path).path
        prefix = "/repos/" + REPO
        body = self.body()
        if path == prefix + "/releases":
            value = json.loads(body)
            release_id = len(self.server.releases) + 10
            value.update(id=release_id, immutable=False)
            self.server.releases[release_id] = value
            self.server.assets[release_id] = {}
            return self.send(201, value)
        if path.endswith("/assets"):
            release_id = int(path.split("/")[-2])
            name = parse_qs(urlsplit(self.path).query)["name"][0]
            if name in self.server.assets[release_id]:
                return self.send(422, {})
            asset_id = 100 + sum(len(a) for a in self.server.assets.values())
            value = {"id": asset_id, "name": name, "state": "uploaded", "size": len(body), "digest": "sha256:" + hashlib.sha256(body).hexdigest(), "data": body}
            self.server.assets[release_id][name] = value
            return self.send(201, self.asset_meta(value))
        if path == prefix + "/git/refs":
            value = json.loads(body)
            self.server.tag_commit = value["sha"]
            return self.send(201, value)
        return self.send(404, {})

    def do_PATCH(self):
        self.request_record()
        release_id = int(urlsplit(self.path).path.rsplit("/", 1)[1])
        value = json.loads(self.body())
        self.server.releases[release_id].update(value)
        if value.get("draft") is False:
            self.server.latest = self.server.releases[release_id]
        self.send(200, self.server.releases[release_id])


class GitHubPublicationTests(unittest.TestCase):
    def setUp(self):
        github._COOLDOWNS.clear()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        assets = {}
        for name in github.ASSETS:
            path = root / name
            path.write_bytes(("test " + name).encode())
            assets[name] = path
        source_bytes = b"synthetic source archive"
        manifest = {"source_zip_sha256": hashlib.sha256(source_bytes).hexdigest(), "assets": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in assets.items()}}
        self.bundle = SimpleNamespace(root=root, version="1.14.9", source_commit=COMMIT, build_commit=COMMIT, assets=assets, notes="Tested release notes", source_zip=root / "source.zip", manifest=manifest, bundle_id="d" * 64)
        self.bundle.source_zip.write_bytes(source_bytes)
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.bundle.manifest_sha256 = hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()
        self.bundle.asset_sizes = {name: path.stat().st_size for name, path in assets.items()}
        (root / "RELEASE_NOTES.md").write_text(self.bundle.notes, encoding="utf-8")
        self.private_key = Ed25519PrivateKey.generate()
        public = self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.addCleanup(patch.stopall)
        patch("release_tools.bundle.revalidate_bundle", side_effect=lambda bundle: bundle).start()
        patch("release_tools.trust.revalidate_bundle", side_effect=lambda bundle: bundle).start()
        patch.dict(trust.TRUSTED_APPROVAL_KEYS, {"test-key": base64.b64encode(public).decode()}).start()
        self.approval = sign_test_approval(self.bundle, self.private_key, "test-key")
        (root / "approval.json").write_text(json.dumps(self.approval), encoding="utf-8")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeAPI)
        self.server.requests, self.server.releases, self.server.assets = [], {}, {}
        self.server.tag_commit, self.server.compare_status, self.server.ci_status = COMMIT, "ahead", "success"
        self.server.latest, self.server.failure, self.server.redirect = None, None, None
        self.server.active_runs = []
        self.server.failure_message = TOKEN
        self.server.hide_drafts = False
        self.server.split_failure = False
        self.server.cdn_data = b"cdn-test"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.hosts = []
        def factory(host, **kwargs):
            self.hosts.append(host)
            return http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        self.client = github.GitHubClient(TOKEN, _connection_factory=factory)
        environment = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                       "GITHUB_REPOSITORY": REPO, "GITHUB_RUN_ID": "99",
                       "GITHUB_SHA": COMMIT, "GITHUB_REF": "refs/heads/main"}
        patch.dict(os.environ, environment).start()

    def publish(self):
        return github.publish_github(self.bundle, REPO, TOKEN, _client=self.client)

    def test_publish_exact_bytes_then_idempotent_resume(self):
        report = self.publish()
        self.assertEqual(report["status"], "published")
        self.assertEqual(set(report["assets"]), github.ASSETS)
        mutations = sum(method in {"POST", "PATCH"} for method, _, _ in self.server.requests)
        self.assertEqual(self.publish()["status"], "already_published")
        self.assertEqual(sum(method in {"POST", "PATCH"} for method, _, _ in self.server.requests), mutations)
        self.assertTrue(any(auth is None and "/releases/assets/" in path for _, path, auth in self.server.requests))
        self.assertFalse(any(method in {"DELETE", "PUT"} for method, _, _ in self.server.requests))

    def test_existing_conflicting_asset_never_deleted_or_replaced(self):
        self.server.releases[10] = {"id": 10, "tag_name": "v1.14.9", "draft": True, "prerelease": False}
        self.server.assets[10] = {"CHANGELOG.md": {"id": 100, "name": "CHANGELOG.md", "state": "uploaded", "size": 3, "digest": "sha256:" + "0" * 64, "data": b"bad"}}
        with self.assertRaisesRegex(github.GitHubError, "asset_conflict"):
            self.publish()
        self.assertFalse(any(method in {"POST", "PATCH", "DELETE", "PUT"} for method, _, _ in self.server.requests))

    def test_tag_mismatch_prerelease_missing_ci_and_downgrade_block_before_writes(self):
        cases = [("tag_commit", "f" * 40, "tag_conflict"), ("ci_status", "failure", "successful_trusted_ci_required"), ("compare_status", "behind", "approved_commit_not_in_default_branch"), ("latest", {"tag_name": "v2.0.0"}, "latest_downgrade"), ("active_runs", [{"id": 42}], "release_workflow_running")]
        for name, value, error in cases:
            with self.subTest(error=error):
                previous = getattr(self.server, name)
                setattr(self.server, name, value)
                with self.assertRaisesRegex(github.GitHubError, error):
                    self.publish()
                setattr(self.server, name, previous)
        self.bundle.version = "1.15.0-staging.2"
        with self.assertRaises(github.GitHubError):
            self.publish()
        self.assertFalse(any(method in {"POST", "PATCH"} for method, _, _ in self.server.requests))

    def test_cancel_and_auth_errors_are_sanitized(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaisesRegex(github.GitHubError, "cancelled"):
            github.publish_github(self.bundle, REPO, TOKEN, cancel=cancel, _client=self.client)
        self.assertEqual(self.server.requests, [])
        self.server.failure = (401, {})
        with self.assertRaises(github.GitHubError) as raised:
            self.publish()
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertEqual(raised.exception.code, "authentication_required")

    def test_rate_limit_wait_hint_without_blind_retry(self):
        self.server.failure = (429, {"Retry-After": "73"})
        with self.assertRaises(github.GitHubError) as raised:
            self.client.json("GET", "/user")
        self.assertEqual(raised.exception.retry_after, 73)
        self.assertEqual(len(self.server.requests), 1)

    def test_secondary_limit_without_headers_and_shared_cooldown(self):
        self.server.failure = (403, {})
        self.server.failure_message = "You have exceeded a secondary rate limit."
        self.server.split_failure = True
        with self.assertRaises(github.GitHubError) as raised:
            self.client.json("GET", "/user")
        self.assertEqual(raised.exception.code, "rate_limited")
        self.assertEqual(raised.exception.retry_after, 60)
        other = github.GitHubClient(TOKEN, _connection_factory=self.client._factory)
        with self.assertRaisesRegex(github.GitHubError, "rate_limited"):
            other.json("GET", "/user")
        self.assertEqual(len(self.server.requests), 1)

    def test_primary_limit_reset_is_utc_and_malformed_reset_is_safe(self):
        self.server.failure = (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "inf"})
        with self.assertRaises(github.GitHubError) as raised:
            self.client.json("GET", "/user")
        self.assertEqual(raised.exception.retry_after, 60)
        github._COOLDOWNS.clear()
        self.server.failure = (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1075"})
        with patch("release_tools.github.time.time", return_value=1000):
            with self.assertRaises(github.GitHubError) as raised:
                self.client.json("GET", "/user")
        self.assertEqual(raised.exception.retry_after, 75)

    def test_redirect_rejects_foreign_host_and_strips_auth_on_cdn(self):
        self.server.redirect = "https://evil.example/steal"
        with self.assertRaisesRegex(github.GitHubError, "unsafe_redirect"):
            self.client._request("GET", "https://api.github.com/repos/a/b/releases/assets/1", redirects=True)
        self.assertNotIn("evil.example", self.hosts)
        self.server.redirect = "https://release-assets.githubusercontent.com/cdn-asset"
        data, _ = self.client._request("GET", "https://api.github.com/repos/a/b/releases/assets/1", redirects=True)
        self.assertEqual(data, self.server.cdn_data)
        self.assertIsNone(self.server.requests[-1][2])

    def test_signed_approval_is_exact_and_domain_separated(self):
        self.assertTrue(trust.verify_approval(self.bundle)["verified"])
        self.bundle.notes += " changed"
        with self.assertRaisesRegex(trust.TrustError, "approval_identity"):
            trust.verify_approval(self.bundle)
        self.bundle.notes = "Tested release notes"
        invalid = dict(self.approval, signature=base64.b64encode(self.private_key.sign(b"wrong domain")).decode())
        with self.assertRaisesRegex(trust.TrustError, "approval_signature"):
            trust.verify_approval(self.bundle, invalid)

    def test_unsigned_bundle_stops_before_network(self):
        (self.bundle.root / "approval.json").unlink()
        with self.assertRaisesRegex(github.GitHubError, "approval_required"):
            self.publish()
        self.assertEqual(self.server.requests, [])

    def test_partial_draft_hidden_from_by_tag_is_resumed_from_list(self):
        self.server.hide_drafts = True
        self.server.releases[10] = {"id": 10, "tag_name": "v1.14.9", "draft": True, "prerelease": False}
        self.server.assets[10] = {}
        self.assertEqual(self.publish()["status"], "published")
        self.assertFalse(any(method == "POST" and path == "/repos/" + REPO + "/releases" for method, path, _ in self.server.requests))


    def test_existing_published_conflicts_fail_without_any_writes(self):
        release = {"id": 10, "tag_name": "v1.14.9", "draft": False, "prerelease": False, "body": self.bundle.notes}
        self.server.releases[10] = self.server.latest = release
        values = {}
        for asset_id, (name, path) in enumerate(self.bundle.assets.items(), start=100):
            data = path.read_bytes()
            values[name] = {"id": asset_id, "name": name, "state": "uploaded", "size": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "data": data}
        self.server.assets[10] = values
        self.assertEqual(self.publish()["status"], "already_published")
        original = values["CHANGELOG.md"]["digest"]
        values["CHANGELOG.md"]["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(github.GitHubError, "asset_conflict"):
            self.publish()
        values["CHANGELOG.md"]["digest"] = None
        self.assertEqual(self.publish()["status"], "already_published")
        values["CHANGELOG.md"]["digest"] = original
        release["body"] = "Wrong notes"
        with self.assertRaisesRegex(github.GitHubError, "release_notes_conflict"):
            self.publish()
        self.assertFalse(any(method != "GET" for method, _, _ in self.server.requests))

    def test_transport_bounds_large_response(self):
        with self.assertRaisesRegex(github.GitHubError, "response_too_large"):
            self.client._request("GET", "https://api.github.com/user", max_bytes=2)

    def test_same_size_upload_tamper_is_rejected_before_any_http(self):
        path = self.bundle.assets["CHANGELOG.md"]
        expected = path.read_bytes()
        path.write_bytes(b"x" * len(expected))
        with self.assertRaisesRegex(github.GitHubError, "bundle_changed"):
            self.client.json("POST", "/repos/" + REPO + "/releases/10/assets?name=CHANGELOG.md", upload=path, size=len(expected), sha256=hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.server.requests, [])

    def test_upload_uses_frozen_handle_when_origin_changes_after_snapshot(self):
        path = self.bundle.assets["CHANGELOG.md"]
        expected = path.read_bytes()
        self.server.releases[10] = {"id": 10, "tag_name": "v1.14.9", "draft": True, "prerelease": False}
        self.server.assets[10] = {}
        factory = self.client._factory
        def mutate_after_snapshot(host, **kwargs):
            path.write_bytes(b"x" * len(expected))
            return factory(host, **kwargs)
        self.client._factory = mutate_after_snapshot
        self.client.json("POST", "/repos/" + REPO + "/releases/10/assets?name=CHANGELOG.md", upload=path, size=len(expected), sha256=hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.server.assets[10]["CHANGELOG.md"]["data"], expected)

    def test_cancel_during_upload_leaves_resumable_draft(self):
        cancel = threading.Event()
        self.client.cancel = cancel
        self.client.emit = lambda event: cancel.set() if event["phase"] == "uploading" else None
        with self.assertRaisesRegex(github.GitHubError, "cancelled"):
            github.publish_github(self.bundle, REPO, TOKEN, cancel=cancel, _client=self.client)
        self.assertTrue(next(iter(self.server.releases.values()))["draft"])
        self.assertFalse(any(method in {"PATCH", "DELETE"} for method, _, _ in self.server.requests))

    def test_signed_input_download_rejects_extra_or_traversal_files(self):
        self.server.releases[10] = {"id": 10, "tag_name": "publisher-input-" + self.bundle.bundle_id, "draft": True, "prerelease": False}
        for bad_name in ("../escape.py", "windows.py", "assets/PRIVATE_DO_NOT_PUBLISH.exe"):
            with self.subTest(name=bad_name):
                content = io.BytesIO()
                with zipfile.ZipFile(content, "w") as archive:
                    archive.writestr(bad_name, "raise RuntimeError('must never execute')")
                data = content.getvalue()
                self.server.assets[10] = {github.INPUT_ASSET: {"id": 100, "name": github.INPUT_ASSET, "state": "uploaded", "size": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "data": data}}
                with self.assertRaisesRegex(github.GitHubError, "bundle_archive"):
                    github.download_draft_bundle(REPO, TOKEN, 10, 100, hashlib.sha256(data).hexdigest(), self.bundle.root / ("extract-" + str(len(self.server.requests))), _client=self.client)
        self.assertFalse((self.bundle.root / "escape.py").exists())


    def test_public_promotion_requires_trusted_actions_context_before_writes(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(github.GitHubError, "trusted_actions_context_required"):
                self.publish()
        self.assertEqual(self.server.requests, [])

    def test_bootstrap_requires_api_verified_actions_context(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(github.GitHubError, "trusted_actions_context_required"):
                github.create_missing_tag_for_actions(self.bundle, REPO, TOKEN, _client=self.client)
        environment = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": REPO, "GITHUB_RUN_ID": "99", "GITHUB_SHA": COMMIT, "GITHUB_REF": "refs/heads/main"}
        self.server.tag_commit = None
        self.server.active_runs = [{"id": 100, "status": "queued"}]
        with patch.dict(os.environ, environment):
            result = github.create_missing_tag_for_actions(self.bundle, REPO, TOKEN, _client=self.client)
        self.assertEqual(result["status"], "tag_verified")
        self.assertEqual(self.server.tag_commit, COMMIT)
        self.assertFalse(any(path == "/user" for _, path, _ in self.server.requests))


if __name__ == "__main__":
    unittest.main()
