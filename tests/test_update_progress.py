import hashlib
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from utils import update_check, update_progress


class ProgressStateTest(unittest.TestCase):
    def setUp(self):
        self.patch = mock.patch.object(update_progress, "_state", {
            "active": False, "phase": "idle", "downloaded": 0, "total": None, "version": ""})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_clear_cannot_erase_active_operation_and_snapshots_are_detached(self):
        run = update_progress.begin("1.14.8")
        update_progress.start_download(run, "1.14.8", 100)
        update_progress.set_download(run, 25, 100)
        self.assertFalse(update_progress.clear_finished())
        state = update_progress.get_progress()
        state.update(active=False, downloaded=999)
        self.assertEqual(update_progress.get_progress()["downloaded"], 25)
        self.assertTrue(update_progress.get_progress()["active"])
        self.assertTrue(update_progress.fail(run))
        self.assertTrue(update_progress.clear_finished())
        self.assertEqual(update_progress.get_progress(), {"active": False, "phase": "idle",
            "downloaded": 0, "total": None, "version": ""})

    def test_failed_run_callbacks_cannot_clobber_retry_or_resurrect_terminal_state(self):
        first = update_progress.begin("1.14.8")
        update_progress.start_download(first, "1.14.8", 100)
        update_progress.fail(first)
        self.assertFalse(update_progress.set_phase(first, "restarting"))
        second = update_progress.begin("1.14.9")
        update_progress.start_download(second, "1.14.9", 200)
        before = update_progress.get_progress()
        for callback in (lambda: update_progress.set_download(first, 100, 100),
                         lambda: update_progress.start_download(first, "1.14.8", 100),
                         lambda: update_progress.set_phase(first, "restarting"),
                         lambda: update_progress.fail(first)):
            self.assertFalse(callback())
        self.assertEqual(update_progress.get_progress(), before)
        self.assertNotEqual(first, second)

    def test_fallback_replaces_version_and_resets_download_denominator(self):
        run = update_progress.begin("1.14.8")
        update_progress.start_download(run, "1.14.8", 100)
        update_progress.set_download(run, 75, 100)
        update_progress.set_phase(run, "verifying")
        update_progress.start_download(run, "1.14.9", 150)
        self.assertEqual(update_progress.get_progress(), {"active": True, "phase": "downloading",
            "downloaded": 0, "total": 150, "version": "1.14.9"})

    def test_only_safe_version_and_closed_public_fields_are_exposed(self):
        for version in ("https://private.example/token", "1.14.8\nPRIVATE", {"secret": "PRIVATE"}):
            with self.subTest(version=type(version).__name__):
                run = update_progress.begin(version)
                update_progress.start_download(run, version)
                self.assertEqual(set(update_progress.get_progress()),
                    {"active", "phase", "downloaded", "total", "version"})
                self.assertNotIn("PRIVATE", json.dumps(update_progress.get_progress()))
                self.assertEqual(update_progress.get_progress()["version"], "")
        run = update_progress.begin("1.15.0-staging.2")
        self.assertEqual(update_progress.get_progress()["version"], "1.15.0-staging.2")
        with self.assertRaises(ValueError):
            update_progress.set_phase(run, "installed")

    def test_unknown_total_and_late_download_updates_do_not_regress_verification(self):
        run = update_progress.begin("1.14.8")
        update_progress.start_download(run, "1.14.8")
        update_progress.set_download(run, 45, None)
        self.assertIsNone(update_progress.get_progress()["total"])
        update_progress.set_phase(run, "verifying")
        self.assertFalse(update_progress.set_download(run, 46, 99))
        self.assertEqual(update_progress.get_progress()["phase"], "verifying")

    def test_concurrent_old_generation_updates_cannot_change_new_run(self):
        first = update_progress.begin("1.14.8")
        second = update_progress.begin("1.14.9")
        update_progress.start_download(second, "1.14.9", 100)
        before = update_progress.get_progress()
        threads = [threading.Thread(target=lambda: [update_progress.set_download(first, i, 50)
            for i in range(100)]) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
        self.assertEqual(update_progress.get_progress(), before)


class ChunkedResponse(io.BytesIO):
    def __init__(self, chunks, clock):
        super().__init__()
        self.chunks = iter(chunks)
        self.clock = clock
        self.headers = {"Content-Length": "999999999999"}

    def geturl(self):
        return "https://example.invalid/release"

    def read1(self, size=-1):
        self.clock[0] += .04
        value = next(self.chunks, b"")
        if isinstance(value, Exception):
            raise value
        return value


class StreamingProgressTest(unittest.TestCase):
    def download(self, chunks, *, size=None, digest=None, progress=None, on_verifying=None):
        clock = [10.0]
        response = ChunkedResponse(chunks, clock)
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(update_check, "_open_response", return_value=response), \
                mock.patch.object(update_check.time, "monotonic", side_effect=lambda: clock[0]):
            try:
                path = update_check.download_asset("https://example.invalid/release", Path(directory),
                    digest=digest or "sha256:" + hashlib.sha256(b"".join(chunks)).hexdigest(), size=size,
                    progress=progress, on_verifying=on_verifying)
                return path.read_bytes()
            except BaseException:
                self.assertEqual(list(Path(directory).iterdir()), [])
                raise

    def test_streamed_byte_counts_are_throttled_and_final_is_exact(self):
        chunks = [b"a" * i for i in range(1, 11)]
        events, phases = [], []
        self.assertEqual(self.download(chunks, size=55, progress=lambda *e: events.append(e),
            on_verifying=lambda: phases.append("verifying")), b"".join(chunks))
        # Three chunks per >=.1 second update, with explicit initial and final events.
        self.assertEqual(events, [(0, 55), (6, 55), (21, 55), (45, 55), (55, 55)])
        self.assertEqual(phases, ["verifying"])

    def test_unknown_size_ignores_http_content_length(self):
        events = []
        self.download([b"data"], progress=lambda *e: events.append(e))
        self.assertEqual(events, [(0, None), (4, None)])

    def test_callback_failures_cannot_change_download_or_its_verification(self):
        def broken(*_):
            raise RuntimeError("PRIVATE callback failure")
        self.assertEqual(self.download([b"data"], size=4, progress=broken, on_verifying=broken), b"data")
        with self.assertRaisesRegex(OSError, "SHA-256"):
            self.download([b"data"], size=4, digest="sha256:" + "0" * 64,
                          progress=broken, on_verifying=broken)

    def test_hash_and_size_failures_are_not_reported_as_installed(self):
        for size, digest in ((4, "sha256:" + "0" * 64), (5, None), (3, None)):
            with self.subTest(size=size), self.assertRaises(OSError):
                self.download([b"data"], size=size, digest=digest, progress=lambda count, total: None)

    def test_stream_error_reports_final_actual_count_before_fallback(self):
        events = []
        with self.assertRaises(TimeoutError):
            self.download([b"data", TimeoutError("PRIVATE")], digest="sha256:" + "0" * 64,
                          progress=lambda *e: events.append(e))
        self.assertEqual(events, [(0, None), (4, None)])

    def test_fallback_emits_actual_candidate_then_resets_progress(self):
        payload = b"backup"
        asset = {"name": "TgWsProxy_windows.exe", "url": "https://github.invalid/a.exe",
            "digest": "sha256:" + "0" * 64, "size": 100, "source": "github",
            "version": "1.14.8", "current_version": "1.14.7", "manifest_url": "https://backup.invalid/latest.json"}
        backup_asset = {**asset, "source": "backup", "version": "1.14.9", "size": len(payload),
            "url": "https://backup.invalid/a.exe", "digest": "sha256:" + hashlib.sha256(payload).hexdigest()}
        clock = [10.0]
        responses = [ChunkedResponse([b"partial", TimeoutError("offline")], clock),
                     ChunkedResponse([payload], clock)]
        events = []
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(update_check, "fetch_backup_release", return_value={
                    "latest": "1.14.9", "assets": [backup_asset]}), \
                mock.patch.object(update_check, "_open_response", side_effect=responses), \
                mock.patch.object(update_check.time, "monotonic", side_effect=lambda: clock[0]):
            path, actual = update_check.download_release_asset(asset, Path(directory),
                progress=lambda count, total: events.append(("bytes", count, total)),
                on_verifying=lambda: events.append(("phase", "verifying")),
                on_candidate=lambda candidate: events.append(("candidate", candidate["version"], candidate["size"])))
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)
        self.assertEqual(actual["version"], "1.14.9")
        self.assertEqual(events, [("candidate", "1.14.8", 100), ("bytes", 0, 100), ("bytes", 7, 100),
            ("candidate", "1.14.9", 6), ("bytes", 0, 6), ("bytes", 6, 6), ("phase", "verifying")])
