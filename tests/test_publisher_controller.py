"""Publisher worker ownership and public receipt boundaries, without network or keys."""
import json
import threading
import time
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from publisher.controller import JobRunner, safe_code
from publisher.state import ASSET_NAMES, PublicationState, StateError


def bundle_fixture(**changes):
    values = dict(bundle_id="a" * 64, version="1.2.3", source_commit="b" * 40,
                  manifest={"assets": {name: "c" * 64 for name in ASSET_NAMES}})
    values.update(changes)
    return SimpleNamespace(**values)


class JobRunnerTests(unittest.TestCase):
    def setUp(self):
        self.runner = JobRunner()
        self.release = threading.Event()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        self.release.set()
        self.runner.request_cancel()
        if self.runner._thread is not None:
            self.runner._thread.join(3)
        self.runner.close()

    def finish(self):
        self.runner._thread.join(3)
        self.assertFalse(self.runner._thread.is_alive(), "Synthetic worker failed to finish")
        return self.runner.poll()

    def test_cancellation_keeps_busy_until_cleanup_and_final_is_consumed(self):
        entered, cleaning = threading.Event(), threading.Event()
        def work(emit, cancel):
            entered.set()
            try:
                self.assertTrue(cancel.wait(3))
            finally:
                cleaning.set()
                self.assertTrue(self.release.wait(3))
            return "cleaned"
        self.assertTrue(self.runner.start(work))
        self.assertTrue(entered.wait(3))
        self.runner.request_cancel()
        self.assertTrue(cleaning.wait(3))
        self.assertTrue(self.runner.busy)
        self.assertFalse(self.runner.start(lambda *_: None))
        self.assertEqual(self.runner.poll(), [])
        self.release.set()
        self.runner._thread.join(3)
        self.assertTrue(self.runner.busy, "Retry must wait for UI consumption of cleanup completion")
        self.assertEqual(self.runner.poll()[0]["value"], "cleaned")
        self.assertTrue(self.runner.start(lambda *_: "retry"))
        self.assertEqual(self.finish()[0]["value"], "retry")

    def test_thread_start_failure_reports_safe_error_and_allows_retry(self):
        secret = "synthetic-private-start-failure"
        with mock.patch.object(threading.Thread, "start", side_effect=RuntimeError(secret)):
            self.assertTrue(self.runner.start(lambda *_: self.fail("Worker must not run")))
        events = self.runner.poll()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "error")
        self.assertEqual(events[0]["code"], "operation_failed")
        self.assertNotIn(secret, json.dumps(events))
        self.assertFalse(self.runner.busy)
        self.assertTrue(self.runner.start(lambda *_: "retry"))
        self.assertEqual(self.finish()[0]["value"], "retry")

    def test_thread_construction_failure_can_close_without_joining_unstarted_thread(self):
        with mock.patch("publisher.controller.threading.Thread", side_effect=RuntimeError("resource limit")):
            self.assertTrue(self.runner.start(lambda *_: None))
        self.assertEqual(self.runner.poll()[0]["kind"], "error")
        self.assertTrue(self.runner.close())

    def test_progress_flood_is_bounded_and_final_survives_concurrent_emitters(self):
        def work(emit, cancel):
            threads = [threading.Thread(target=lambda: [emit({"phase": "upload", "bytes": n})
                                                        for n in range(600)]) for _ in range(3)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            return "published"
        self.assertTrue(self.runner.start(work))
        self.runner._thread.join(3)
        self.assertLessEqual(self.runner.events.qsize(), 256)
        events = self.finish()
        self.assertEqual([e["value"] for e in events if e["kind"] == "complete"], ["published"])
        self.assertFalse(self.runner.busy)

    def test_late_previous_generation_is_ignored(self):
        captured = []
        self.runner.start(lambda emit, cancel: captured.append(emit))
        self.finish()
        entered = threading.Event()
        def next_job(emit, cancel):
            entered.set()
            self.release.wait(3)
            return "new"
        self.runner.start(next_job)
        self.assertTrue(entered.wait(3))
        captured[0]({"phase": "published", "bytes": 99})
        self.assertEqual(self.runner.poll(), [])
        self.assertTrue(self.runner.busy)
        self.release.set()
        self.assertEqual(self.finish()[0]["value"], "new")

    def test_close_cancels_and_prevents_restart_during_cleanup(self):
        entered = threading.Event()
        self.runner.start(lambda emit, cancel: (entered.set(), self.release.wait(3)))
        self.assertTrue(entered.wait(3))
        self.assertFalse(self.runner.close())
        self.assertTrue(self.runner.cancel.is_set())
        self.assertFalse(self.runner.start(lambda *_: None))
        self.release.set()
        self.runner._thread.join(3)
        self.assertTrue(self.runner.close())
        self.assertEqual(self.runner.poll(), [])
        self.assertFalse(self.runner.start(lambda *_: None))

    def test_events_and_errors_do_not_expose_synthetic_credentials(self):
        secret = "ghp_synthetic_lowercase_secret"
        class SecretError(Exception):
            code = secret
            committed = "yes"
            retry_after = float("inf")
        def work(emit, cancel):
            emit({"phase": secret, "code": secret, "channel": secret, "password": secret,
                  "bytes": float("nan"), "total": float("inf"), "done": True,
                  "wait_seconds": -1, "raw_exception": secret})
            raise SecretError(secret)
        self.runner.start(work)
        events = self.finish()
        self.assertEqual(events[0]["event"], {"phase": "operation", "code": "operation_failed"})
        self.assertEqual(events[1]["code"], "operation_failed")
        self.assertFalse(events[1]["committed"])
        self.assertNotIn(secret, json.dumps(events))
        self.assertEqual(safe_code(SimpleNamespace(code="rate_limited")), "rate_limited")

    def test_hostile_exception_attributes_still_deliver_final_error(self):
        class HostileError(Exception):
            @property
            def code(self):
                raise ValueError("synthetic secret")
            committed = code
            retry_after = code
        def work(*_):
            raise HostileError("synthetic private message")
        self.runner.start(work)
        event = self.finish()[0]
        self.assertEqual(event["code"], "operation_failed")
        self.assertFalse(event["committed"])
        self.assertNotIn("retry_after", event)
        self.assertFalse(self.runner.busy)

    def test_rate_delay_is_finite_bounded_metadata(self):
        class RateError(Exception):
            code = "rate_limited"
            retry_after = 2.25
            committed = True
        def work(*_):
            raise RateError("private network response")
        self.runner.start(work)
        event = self.finish()[0]
        self.assertEqual(event["retry_after"], 3)
        self.assertTrue(event["committed"])


class PublicationStateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="publisher-receipts-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name).resolve() / "history.json"
        self.store = PublicationState(self.path)
        self.bundle = bundle_fixture()

    def test_receipts_are_scoped_to_bundle_channel_and_target(self):
        success = {"status": "published", "verified": True, "manifest_url": "https://updates.example.invalid/latest.json"}
        self.store.record(self.bundle, "server", "server-one", success)
        self.store.record(self.bundle, "github", "owner/repo", {"status": "failed", "code": "authentication"})
        self.store.record(self.bundle, "server", "server-two", {"status": "pending"})
        next_bundle = bundle_fixture(bundle_id="d" * 64, version="1.2.4")
        self.store.record(next_bundle, "server", "server-one", {"status": "queued", "verified": True})
        rows = self.store.load()
        self.assertEqual(len(rows), 4)
        self.assertTrue(rows[self.store.key(self.bundle.bundle_id, "server", "server-one")]["verified"])
        self.assertEqual(rows[self.store.key(self.bundle.bundle_id, "github", "owner/repo")]["status"], "failed")
        self.assertFalse(rows[self.store.key(next_bundle.bundle_id, "server", "server-one")]["verified"])
        pending = self.store.record(self.bundle, "github", "owner/repo", {
            "status": "dispatch_unconfirmed", "verified": True,
            "release_url": "https://github.com/owner/repo/releases/1"})
        self.assertEqual(pending["status"], "dispatch_unconfirmed")
        self.assertFalse(pending["verified"])
        self.assertEqual(self.store.load()[self.store.key(self.bundle.bundle_id, "github", "owner/repo")], pending)

    def test_only_public_protocol_fields_are_saved(self):
        secret = "synthetic_lowercase_secret"
        receipt = self.store.record(self.bundle, "github", "owner/repo", {
            "status": secret, "code": secret, "verified": True, "committed": "yes",
            "password": secret, "token": secret, "exception": secret,
            "release_url": "https://github.com/owner/repo/releases/tag/v1.2.3?token=" + secret,
            "workflow_url": "https://user:password@github.com/owner/repo/actions/runs/1",
            "manifest_url": "https://updates.example.invalid/latest.json#" + secret,
        })
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["code"], "operation_failed")
        self.assertFalse(receipt["verified"])
        self.assertFalse(receipt["committed"])
        saved = self.path.read_text(encoding="utf-8")
        for forbidden in (secret, "password", "token", "exception", "workflow_url", "release_url", "manifest_url"):
            self.assertNotIn(forbidden, saved)

    def test_malformed_or_secret_bearing_history_is_preserved_and_rejected(self):
        self.store.record(self.bundle, "github", "owner/repo", {"status": "queued"})
        value = json.loads(self.path.read_text(encoding="utf-8"))
        next(iter(value["receipts"].values()))["token"] = "SYNTHETIC_PRIVATE_TOKEN"
        original = json.dumps(value).encode()
        self.path.write_bytes(original)
        with self.assertRaises(StateError):
            self.store.load()
        with self.assertRaises(StateError):
            self.store.record(self.bundle, "server", "target", {"status": "published"})
        self.assertEqual(self.path.read_bytes(), original)

    def test_identity_and_scalar_bounds_fail_before_writing(self):
        for bundle in (bundle_fixture(version="1.2.3-staging.1"),
                       bundle_fixture(version="9" * 1000),
                       bundle_fixture(source_commit="synthetic_private_path"),
                       bundle_fixture(manifest={"assets": {"unexpected.exe": "a" * 64}})):
            with self.subTest(bundle=bundle.version):
                with self.assertRaises(StateError):
                    self.store.record(bundle, "server", "target", {"status": "published"})
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
