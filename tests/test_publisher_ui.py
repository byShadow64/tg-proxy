"""One isolated native Publisher interpreter; no actual accounts, keys or network."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


_NATIVE_MODE = "--native-run" in sys.argv


if not _NATIVE_MODE:
    class PublisherUIProcessTest(unittest.TestCase):
        def test_isolated_native_publisher_scenarios(self):
            with tempfile.TemporaryDirectory(prefix="publisher-native-") as directory:
                root = Path(directory).resolve()
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", TG_PROXY_PUBLISHER_TEST_ROOT=str(root))
                for name in ("APPDATA", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"):
                    target = root / name.lower()
                    target.mkdir()
                    env[name] = str(target.resolve())
                result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--native-run"],
                                        capture_output=True, text=True, encoding="utf-8", errors="replace",
                                        env=env, timeout=70)
            if "NATIVE_DISPLAY_UNAVAILABLE" in result.stdout:
                self.skipTest("Native Tk display is unavailable")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Ran 13 tests", result.stderr)


if _NATIVE_MODE:
    # All private directories were replaced in the parent before these imports.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import hashlib
    import json
    import threading
    import time
    from contextlib import ExitStack
    from dataclasses import replace
    from types import SimpleNamespace
    from unittest import mock
    from tkinter import TclError

    import customtkinter as ctk
    from publisher import app as app_module
    from publisher import github, server, trust
    from publisher.controller import JobRunner
    from publisher.profiles import ServerProfile
    from publisher.state import ASSET_NAMES, PublicationState
    from proxy.update_channel import UPDATE_MANIFEST_URL

    SECRET = "synthetic_private_token_no_real_credentials"

    def profile_fixture():
        return ServerProfile(host="updates.example.invalid", base_url="https://updates.example.invalid",
                             host_key="SHA256:" + "A" * 43, auth_method="password")

    class MemoryStore:
        def __init__(self):
            self.saved_calls = []
        def load(self):
            return [profile_fixture()], {}, "default"
        def save(self, profiles, secrets, active_id):
            self.saved_calls.append((list(profiles), dict(secrets), active_id))

    class MemoryReceipts:
        key = staticmethod(PublicationState.key)
        def __init__(self):
            self.rows, self.calls = {}, []
        def load(self):
            return dict(self.rows)
        def record(self, bundle, channel, target, result):
            self.calls.append((bundle.bundle_id, channel, target, dict(result)))
            self.rows[self.key(bundle.bundle_id, channel, target)] = dict(result)

    class NativePublisherTests(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.root = Path(os.environ["TG_PROXY_PUBLISHER_TEST_ROOT"]).resolve()
            cls.store, cls.receipts = MemoryStore(), MemoryReceipts()
            try:
                cls.app = app_module.PublisherApp(store=cls.store, receipts=cls.receipts)
            except TclError as error:
                print("NATIVE_DISPLAY_UNAVAILABLE")
                raise unittest.SkipTest(str(error)) from error
            cls.app.withdraw()
            cls.main_thread = threading.get_ident()
            bundle_root = cls.root / "synthetic-publication"
            bundle_root.mkdir()
            assets, hashes = {}, {}
            for name in sorted(ASSET_NAMES):
                path = bundle_root / name
                data = ("synthetic public asset " + name).encode()
                path.write_bytes(data)
                assets[name], hashes[name] = path, hashlib.sha256(data).hexdigest()
            cls.bundle = SimpleNamespace(root=bundle_root, version="1.2.3", bundle_id="a" * 64,
                                         source_commit="b" * 40, build_commit="c" * 40,
                                         assets=assets, manifest={"assets": hashes}, notes="Synthetic release notes")

        @classmethod
        def tearDownClass(cls):
            try:
                if cls.app.winfo_exists():
                    cls.app.destroy()
            except TclError:
                pass

        def setUp(self):
            self.app = type(self).app
            self.assertFalse(self.app.runner.busy)
            self.stack = ExitStack()
            self.addCleanup(self.stack.close)
            self.cleanup_gate = threading.Event()
            self.addCleanup(self.cleanup_gate.set)
            self.callback_errors, self.thread_violations = [], []
            self.app.report_callback_exception = lambda *args: self.callback_errors.append(args)
            self.app.bundle, self.app.approval = self.bundle, {"synthetic": True}
            self.app._last_results, self.app._last_link = {}, ""
            self.app._github_cooldown_until = 0
            self.app._closing = False
            self.app.profiles = [profile_fixture()]
            self.app.saved = {}
            self.app._select_profile("default")
            self.app.remember.set(False)
            self.app.want_server.set(True)
            self.app.want_github.set(True)
            self.app.confirmed.set(False)
            self.app.token.delete(0, "end")
            self.app.token.insert(0, SECRET)
            self.app.credential_fields["password"].insert(0, SECRET)
            self.receipts.rows.clear()
            self.receipts.calls.clear()
            self.store.saved_calls.clear()
            for module, names in ((server, ("publish_bundle", "verify_publication", "check_server", "probe_host_key", "approve_local_bundle")),
                                  (github, ("preflight_github", "prepare_github_draft", "dispatch_release_workflow", "verify_github_publication"))):
                for name in names:
                    self.stack.enter_context(mock.patch.object(module, name, side_effect=AssertionError("Unmocked network operation")))
            self.stack.enter_context(mock.patch("socket.create_connection", side_effect=AssertionError("Network forbidden")))
            self.stack.enter_context(mock.patch.object(app_module.webbrowser, "open", side_effect=AssertionError("Browser forbidden")))
            # The test bundle is synthetic data. Approval IO/signature checks
            # have separate backend tests, so never touch a real signing file.
            self.stack.enter_context(mock.patch.object(trust, "load_approval", return_value={"synthetic": True}))
            for name in ("_log", "_show_results", "_set_busy"):
                original = getattr(self.app, name)
                def guarded(*args, _original=original, _name=name, **kwargs):
                    if threading.get_ident() != self.main_thread:
                        self.thread_violations.append(_name)
                        raise AssertionError("Tk callback reached worker")
                    return _original(*args, **kwargs)
                self.stack.enter_context(mock.patch.object(self.app, name, side_effect=guarded))

        def tearDown(self):
            self.cleanup_gate.set()
            self.assertEqual(self.callback_errors, [])
            self.assertEqual(self.thread_violations, [])

        def pump(self, predicate, timeout=4):
            until = time.monotonic() + timeout
            while time.monotonic() < until:
                self.app.update()
                if predicate():
                    return
                time.sleep(.01)
            self.fail("Native publisher did not reach expected state")

        def finish(self):
            self.pump(lambda: not self.app.runner.busy)

        @staticmethod
        def entry_set(widget, value):
            widget.delete(0, "end")
            widget.insert(0, value)

        def test_a_both_themes_and_minimum_size(self):
            self.assertEqual(tuple(map(int, self.app.tk.call("wm", "minsize", self.app._w))),
                             tuple(int(self.app._apply_window_scaling(n)) for n in (860, 640)))
            self.app.geometry("860x640")
            self.app.deiconify()
            for theme in ("dark", "light"):
                ctk.set_appearance_mode(theme)
                for page in ("Пакет", "Назначения", "Публикация", "Журнал"):
                    self.app.tabs.set(page)
                    self.app.update()
                    self.assertEqual(ctk.get_appearance_mode().lower(), theme)
                    self.assertGreater(self.app.tabs.winfo_width(), 700)
                    self.assertLess(self.app.cancel_button.winfo_rooty() + self.app.cancel_button.winfo_height(),
                                    self.app.winfo_rooty() + self.app.winfo_height() + 1)
            self.app.withdraw()

        def test_b_masked_credentials_and_manual_server_do_not_change_client(self):
            for widget in (self.app.token, self.app.credential_fields["password"], self.app.credential_fields["key_passphrase"]):
                self.assertTrue(widget.cget("show"))
            client_path = self.root / "appdata" / "TgWsProxy" / "config.json"
            client_path.parent.mkdir(parents=True, exist_ok=True)
            original = json.dumps({"update_manifest_url": UPDATE_MANIFEST_URL, "synthetic_setting": 42}).encode()
            client_path.write_bytes(original)
            self.app._new_profile()
            new_id = self.app.active_id
            for name, value in {"name": "Alternate", "base_url": "https://alternate.example.invalid",
                                "host": "alternate.example.invalid", "host_key": "SHA256:" + "B" * 43}.items():
                self.entry_set(self.app.fields[name], value)
            self.app._save_settings()
            self.assertEqual(len(self.store.saved_calls), 1)
            profiles, private, active = self.store.saved_calls[0]
            self.assertEqual(active, new_id)
            self.assertEqual(private, {})
            self.assertEqual(profiles[0], profile_fixture())
            self.assertEqual(client_path.read_bytes(), original)
            from proxy import update_channel
            self.assertEqual(update_channel.UPDATE_MANIFEST_URL, UPDATE_MANIFEST_URL)

        def test_c_invalid_new_bundle_clears_old_bundle_and_approval(self):
            class UnsafeError(Exception):
                code = SECRET
            self.app.confirmed.set(True)
            self.app._last_results = {"server": {"status": "published"}}
            with mock.patch.object(app_module, "load_bundle", side_effect=UnsafeError(SECRET)):
                self.app._load_path(self.root / "wrong-package")
                self.assertIsNone(self.app.bundle)
                self.assertIsNone(self.app.approval)
                self.assertFalse(self.app.confirmed.get())
                self.assertEqual(self.app._last_results, {})
                self.finish()
            self.assertIsNone(self.app.bundle)
            self.assertNotIn(SECRET, self.app.status.cget("text"))
            self.assertEqual(self.app.bundle_details.get("1.0", "end").strip(), "")
            self.app._publish()
            self.assertFalse(self.app.runner.busy)
            self.assertIn("выберите", self.app.status.cget("text"))

        def test_d_loading_and_approval_io_stay_in_worker_without_automatic_approval(self):
            threads = []
            def load(path):
                threads.append(threading.get_ident())
                return self.bundle
            def approval(bundle):
                threads.append(threading.get_ident())
                return None
            with mock.patch.object(app_module, "load_bundle", side_effect=load), mock.patch.object(trust, "load_approval", side_effect=approval):
                self.app._load_path(self.bundle.root)
                self.finish()
            self.assertEqual(len(threads), 2)
            self.assertTrue(all(thread != self.main_thread for thread in threads))
            self.assertIs(self.app.bundle, self.bundle)
            self.assertIsNone(self.app.approval)
            self.assertFalse(self.app.confirmed.get())
            self.assertIn(self.bundle.source_commit, self.app.bundle_details.get("1.0", "end"))

        def test_e_server_success_is_preserved_when_github_fails(self):
            class CredentialError(Exception):
                code = "authentication_required"
            with mock.patch.object(server, "publish_bundle", return_value={"status": "published", "verified": True}), \
                    mock.patch.object(github, "preflight_github", side_effect=CredentialError(SECRET)) as preflight, \
                    mock.patch.object(github, "prepare_github_draft") as prepare:
                self.app._publish()
                self.finish()
                self.assertEqual(preflight.call_count, 1)
                prepare.assert_not_called()
            self.assertTrue(self.app._last_results["server"]["verified"])
            self.assertEqual(self.app._last_results["github"]["status"], "failed")
            self.assertEqual(self.app._last_results["github"]["code"], "authentication_required")
            self.assertEqual([row[1] for row in self.receipts.calls], ["server", "github"])
            self.app._copy_report()
            self.assertNotIn(SECRET, self.app.clipboard_get())
            self.assertNotIn(SECRET, self.app.journal.get("1.0", "end"))

        def test_f_github_dispatch_remains_queued_when_server_fails(self):
            class SftpError(Exception):
                code = "sftp"
            with mock.patch.object(server, "publish_bundle", side_effect=SftpError(SECRET)), \
                    mock.patch.object(github, "preflight_github", return_value={"ci": True}), \
                    mock.patch.object(github, "prepare_github_draft", return_value={"draft_url": "https://github.com/example/test/releases/1"}), \
                    mock.patch.object(github, "dispatch_release_workflow", return_value={"workflow_url": "https://github.com/example/test/actions/runs/1"}):
                self.app._publish()
                self.finish()
            self.assertEqual(self.app._last_results["server"]["status"], "failed")
            self.assertEqual(self.app._last_results["github"]["status"], "queued")
            self.assertFalse(self.app._last_results["github"]["verified"])
            self.assertEqual([row[3]["status"] for row in self.receipts.calls], ["failed", "draft_ready", "queued"])

        def test_g_target_checks_are_read_only_and_history_is_target_scoped(self):
            with mock.patch.object(server, "check_server", return_value={"status": "ready", "verified": False}), \
                    mock.patch.object(github, "preflight_github", return_value={"ci": True}):
                self.app._check_targets()
                self.finish()
            self.assertEqual(self.receipts.calls, [])
            self.assertEqual(self.app._last_results["github"], {"status": "ready", "verified": False})
            target = self.app._target(profile_fixture())
            self.receipts.rows[self.receipts.key(self.bundle.bundle_id, "server", target)] = {"status": "published"}
            self.app._refresh_receipts()
            self.assertIn("Опубликовано", self.app.channel_labels["server"].cget("text"))
            self.entry_set(self.app.fields["base_url"], "https://different.example.invalid")
            self.app._refresh_receipts()
            self.assertIn("не проверялось", self.app.channel_labels["server"].cget("text"))

        def test_server_lost_commit_reply_shows_uncertainty_without_claiming_publication(self):
            self.app.want_github.set(False)
            with mock.patch.object(server, "publish_bundle", side_effect=server.ServerError("publication_unconfirmed")) as publish:
                self.app._publish()
                self.finish()
            self.assertEqual(publish.call_count, 1)
            report = self.app._last_results["server"]
            self.assertEqual(report["status"], "publication_unconfirmed")
            self.assertFalse(report["committed"])
            self.assertEqual(self.receipts.calls[0][3]["status"], "publication_unconfirmed")
            self.assertIn("мог принять", self.app.channel_labels["server"].cget("text"))

        def test_h_rate_limit_does_not_block_server_only_retry(self):
            error = github.GitHubError("rate_limited", retry_after=3)
            with mock.patch.object(server, "check_server", return_value={"status": "ready"}) as server_check, \
                    mock.patch.object(github, "preflight_github", side_effect=error) as github_check:
                self.app._check_targets()
                self.finish()
                self.assertEqual(self.app._last_results["github"]["code"], "rate_limited")
                self.app.want_github.set(False)
                self.app._check_targets()
                self.finish()
                self.assertEqual(server_check.call_count, 2)
                self.assertEqual(github_check.call_count, 1)

        def test_i_cancel_waits_for_cleanup_and_retry_is_disabled_until_then(self):
            entered, cleaning = threading.Event(), threading.Event()
            calls = []
            def work(emit, cancel):
                calls.append(1)
                entered.set()
                cancel.wait(3)
                cleaning.set()
                self.cleanup_gate.wait(3)
                return "cleaned"
            self.app._start("Synthetic operation", work, lambda value: calls.append(value))
            self.assertTrue(entered.wait(2))
            self.app._start("Duplicate", work, lambda _: None)
            self.app._cancel()
            self.assertTrue(cleaning.wait(2))
            self.app.update()
            self.assertTrue(self.app.runner.busy)
            self.assertTrue(all(widget.cget("state") == "disabled" for widget, _ in self.app._controls))
            self.assertEqual(self.app.cancel_button.cget("state"), "disabled")
            self.cleanup_gate.set()
            self.finish()
            self.assertEqual(calls, [1, "cleaned"])
            self.app._start("Retry", lambda *_: "retry", calls.append)
            self.finish()
            self.assertEqual(calls[-1], "retry")

        def test_j_hard_conflict_blocks_both_channels_before_server_write(self):
            for code in ("tag_conflict", "immutable_version", "asset_conflict"):
                with self.subTest(code=code), \
                        mock.patch.object(github, "preflight_github", side_effect=github.GitHubError(code)), \
                        mock.patch.object(server, "publish_bundle") as publish, \
                        mock.patch.object(github, "prepare_github_draft") as prepare:
                    self.app._publish()
                    self.finish()
                    publish.assert_not_called()
                    prepare.assert_not_called()
                    self.assertEqual(self.app._last_results["server"], {"status": "failed", "code": "conflict"})
                    self.assertEqual(self.app._last_results["github"]["code"], code)

        def test_k_dispatch_timeout_preserves_draft_without_claiming_workflow_failed(self):
            self.app.want_server.set(False)
            draft = "https://github.com/example/test/releases/1"
            with mock.patch.object(github, "preflight_github", return_value={"ci": True}), \
                    mock.patch.object(github, "prepare_github_draft", return_value={"draft_url": draft}), \
                    mock.patch.object(github, "dispatch_release_workflow", side_effect=github.GitHubError("timeout")):
                self.app._publish()
                self.finish()
            report = self.app._last_results["github"]
            self.assertEqual(report["status"], "dispatch_unconfirmed")
            self.assertEqual(report["release_url"], draft)
            self.assertFalse(report.get("verified", False))
            self.assertIn("не подтверждён", self.app.channel_labels["github"].cget("text"))

        def test_z_close_defers_destroy_until_worker_cleanup(self):
            entered, cleaned = threading.Event(), threading.Event()
            callbacks = []
            def work(emit, cancel):
                entered.set()
                cancel.wait(3)
                self.cleanup_gate.wait(3)
                emit({"phase": "published"})
                cleaned.set()
                return "late result"
            self.app._start("Closing fixture", work, callbacks.append)
            self.assertTrue(entered.wait(2))
            self.app._close()
            self.assertTrue(self.app._closing)
            self.assertTrue(self.app.runner.cancel.is_set())
            self.assertTrue(self.app.winfo_exists())
            self.app._start("Ignored during close", lambda *_: None, callbacks.append)
            self.cleanup_gate.set()
            self.assertTrue(cleaned.wait(3))
            destroyed = []
            original_destroy = self.app.destroy
            def destroy():
                destroyed.append(True)
                original_destroy()
            with mock.patch.object(self.app, "destroy", side_effect=destroy):
                timed_out = []
                self.app.after(4000, lambda: (timed_out.append(True), self.app.destroy()))
                # mainloop stops immediately when Tk is destroyed; update()
                # would keep draining CTk timers after their commands vanished.
                self.app.mainloop()
                self.assertFalse(timed_out)
                self.assertEqual(destroyed, [True])
            self.assertEqual(callbacks, [])


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
