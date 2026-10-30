"""Native sidebar update checks with synthetic releases and no network access."""
import subprocess
import sys
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError, URLError

from tkinter import TclError

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from proxy import __version__
from proxy.project import REPOSITORY
from ui import update_button
from ui.ctk_theme import apply_ctk_appearance, ctk_theme_for_platform
from ui.i18n import get_config_language, set_language, t
from utils import update_check, update_progress

_NATIVE_MODE = "--native-run" in sys.argv


if not _NATIVE_MODE:
    class SidebarUpdatesProcessTest(unittest.TestCase):
        def test_native_sidebar_update_scenarios(self):
            # CTk caches fonts/images in its first Tcl interpreter. Keep this
            # suite independent from the other native UI modules' Tk roots.
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--native-run"],
                capture_output=True, text=True, timeout=35,
            )
            if "NATIVE_DISPLAY_UNAVAILABLE" in result.stdout:
                self.skipTest("Native Tk display is unavailable")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if _NATIVE_MODE:
    class NativeSidebarUpdatesTest(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            import customtkinter as ctk

            cls.ctk = ctk
            try:
                cls.app = ctk.CTk()
            except TclError as exc:
                print("NATIVE_DISPLAY_UNAVAILABLE")
                raise unittest.SkipTest(str(exc)) from exc
            cls.app.withdraw()

        @classmethod
        def tearDownClass(cls):
            if hasattr(cls, "app"):
                cls.app.destroy()

        def setUp(self):
            self.windows = []
            self.errors = []
            self.progress_runs = []
            update_progress.clear_finished()
            self.addCleanup(self.clear_progress)
            self.stack = ExitStack()
            self.addCleanup(self.stack.close)
            self.app.report_callback_exception = lambda *args: self.errors.append(args)
            self.addCleanup(set_language, get_config_language())
            self.addCleanup(self.ctk.set_appearance_mode, self.ctk.get_appearance_mode())
            set_language("en")
            apply_ctk_appearance(self.ctk, "light")
            self.theme = ctk_theme_for_platform()
            state = {
                "checked": False, "has_update": False, "ahead_of_release": False,
                "latest": None, "html_url": update_check.RELEASES_PAGE_URL,
                "error": None, "assets": [],
            }
            self.stack.enter_context(mock.patch.object(update_check, "_state", state))
            self.stack.enter_context(mock.patch.object(update_button.sys, "frozen", True, create=True))
            self.stack.enter_context(mock.patch.object(
                update_button, "asset_name", return_value="TgWsProxy_windows.exe"))
            # These legacy sidebar scenarios mock GitHub only. Signed backup
            # discovery has its own isolated tests and must not contact a server.
            self.stack.enter_context(mock.patch.object(update_check, "UPDATE_MANIFEST_URL", ""))
            self.opener = self.stack.enter_context(mock.patch.object(
                update_check, "build_github_opener", side_effect=AssertionError("Real network is forbidden"),
            ))
            self.download = self.stack.enter_context(mock.patch.object(
                update_check, "download_asset", side_effect=AssertionError("Automatic installation is forbidden"),
            ))
            self.browser = self.stack.enter_context(mock.patch.object(update_button, "open_release_page"))

        def tearDown(self):
            for window in self.windows:
                if window.winfo_exists():
                    window.destroy()
            self.app.update()
            self.opener.assert_not_called()
            self.download.assert_not_called()
            self.assertFalse(self.errors)

        def clear_progress(self):
            for run in self.progress_runs:
                update_progress.fail(run)
            update_progress.clear_finished()

        def begin_download(self, total=None, downloaded=0):
            run = update_progress.begin("99.0.0")
            self.progress_runs.append(run)
            update_progress.start_download(run, "99.0.0", total)
            update_progress.set_download(run, downloaded, total)
            return run

        def pump(self, milliseconds=20):
            ready = self.ctk.BooleanVar(master=self.app, value=False)
            self.app.after(milliseconds, lambda: ready.set(True))
            self.app.wait_variable(ready)
            self.app.update()

        def until(self, predicate, timeout=3):
            deadline = time.monotonic() + timeout
            while not predicate():
                if time.monotonic() >= deadline:
                    self.fail("Native sidebar update task did not finish")
                self.pump()
            self.app.update_idletasks()

        def window(self, size="190x330"):
            window = self.ctk.CTkToplevel(self.app)
            window.withdraw()
            self.windows.append(window)
            window.geometry(f"{size}+12000+12000")
            return window

        def sidebar(self, on_update=None):
            window = self.window()
            parent = self.ctk.CTkFrame(window, fg_color="transparent")
            parent.pack(fill="both", expand=True, padx=24, pady=20)
            view = update_button.SidebarUpdates(self.ctk, parent, self.theme, on_update=on_update)
            view.frame.pack(fill="x")
            window.deiconify()
            self.pump(60)
            return window, view

        def check_release(self, view, version, *, include_asset=True):
            with mock.patch.object(update_check, "fetch_latest_release", return_value={
                "tag_name": f"v{version}", "html_url": update_check.RELEASES_PAGE_URL,
                "assets": [{"name": "TgWsProxy_windows.exe",
                            "browser_download_url": "https://example.org/TgWsProxy_windows.exe",
                            "digest": "sha256:" + "a" * 64, "size": 4096}]
                          if include_asset else [],
            }) as fetch:
                view.button.invoke()
                self.until(lambda: not view.task.running)
                fetch.assert_called_once_with()

        def assertInside(self, widget, parent):
            self.assertTrue(widget.winfo_ismapped())
            x = widget.winfo_rootx() - parent.winfo_rootx()
            y = widget.winfo_rooty() - parent.winfo_rooty()
            self.assertGreaterEqual(x, -1)
            self.assertGreaterEqual(y, -1)
            self.assertLessEqual(x + widget.winfo_width(), parent.winfo_width() + 1)
            self.assertLessEqual(y + widget.winfo_height(), parent.winfo_height() + 1)

        def test_busy_check_disables_button_and_rejects_duplicate_clicks(self):
            callback = mock.Mock()
            _, view = self.sidebar(callback)
            entered, release = threading.Event(), threading.Event()

            def fetch():
                entered.set()
                if not release.wait(3):
                    raise TimeoutError("Synthetic request was not released")
                return {"tag_name": f"v{__version__}"}

            with mock.patch.object(update_check, "fetch_latest_release", side_effect=fetch) as request:
                try:
                    view.button.invoke()
                    self.assertTrue(entered.wait(2))
                    self.assertTrue(view.task.running)
                    self.assertEqual(view.button.cget("state"), "disabled")
                    self.assertEqual(view.button.cget("text"), t("dashboard.update_checking"))
                    self.assertEqual(view.status.cget("text"), t("dashboard.update_wait"))
                    view.button.invoke()
                    view.check()
                    view.open_update()
                    view.refresh()
                    self.pump(60)
                    self.assertEqual(request.call_count, 1)
                    self.assertEqual(view.button.cget("state"), "disabled")
                    callback.assert_not_called()
                    self.browser.assert_not_called()
                finally:
                    release.set()
                    self.until(lambda: not view.task.running)
            self.assertEqual(view.button.cget("state"), "normal")
            self.assertEqual(view.status.cget("text"), "You are up to date")

        def test_equal_newer_and_older_releases_have_distinct_results(self):
            _, view = self.sidebar()
            for version, status, action in (
                (__version__, "You are up to date", False),
                ("99.0.0", "Version 99.0.0 is available", True),
                ("0.0.1", "Newer than the GitHub release", False),
            ):
                with self.subTest(version=version):
                    self.check_release(view, version)
                    self.assertEqual(view.status.cget("text"), status)
                    self.assertEqual(bool(view.action.winfo_ismapped()), action)
                    self.assertEqual(view.button.cget("state"), "normal")
                    self.assertNotIn("dashboard.", view.status.cget("text"))
                    self.browser.assert_not_called()

        def test_available_release_waits_for_explicit_update_action(self):
            callback = mock.Mock()
            _, view = self.sidebar(callback)
            self.check_release(view, "99.0.0")
            callback.assert_not_called()
            self.browser.assert_not_called()
            view.action.invoke()
            callback.assert_called_once_with()
            self.browser.assert_not_called()

        def test_without_installer_callback_explicit_action_opens_this_fork(self):
            _, view = self.sidebar()
            self.assertEqual(update_check.RELEASES_LATEST_API,
                             f"https://api.github.com/repos/{REPOSITORY}/releases/latest")
            self.check_release(view, "99.0.0")
            self.assertEqual(view.action.cget("text"), "Release page")
            self.browser.assert_not_called()
            view.action.invoke()
            self.browser.assert_called_once_with(
                f"https://github.com/{REPOSITORY}/releases/latest",
                parent=view.task.owner,
            )

        def test_verified_github_and_backup_releases_offer_update_in_both_themes_and_languages(self):
            for source in ("github", "backup"):
                for language, label in (("ru", "Обновить"), ("en", "Update")):
                    for appearance in ("light", "dark"):
                        with self.subTest(source=source, language=language, appearance=appearance):
                            set_language(language)
                            apply_ctk_appearance(self.ctk, appearance)
                            callback = mock.Mock()
                            window, view = self.sidebar(callback)
                            if source == "github":
                                self.check_release(view, "99.0.0")
                            else:
                                backup = {
                                    "latest": "99.0.0", "html_url": "https://example.org/releases",
                                    "source": "backup", "assets": [{
                                        "name": "TgWsProxy_windows.exe",
                                        "url": "https://example.org/TgWsProxy_windows.exe",
                                        "digest": "sha256:" + "b" * 64, "size": 8192,
                                    }],
                                }
                                error = HTTPError(update_check.RELEASES_LATEST_API, 404, "Not Found", {}, None)
                                with mock.patch.object(update_check, "UPDATE_MANIFEST_URL", "https://example.org/latest.json"), \
                                        mock.patch.object(update_check, "fetch_latest_release", side_effect=error), \
                                        mock.patch.object(update_check, "fetch_backup_release", return_value=backup):
                                    view.check()
                                    self.until(lambda: not view.task.running)
                            self.assertEqual(update_check.get_status()["source"], source)
                            self.assertEqual(view.action.cget("text"), label)
                            self.assertIsNotNone(view.action.cget("image"))
                            self.assertEqual(view.action.cget("fg_color"), self.theme.accent)
                            self.assertEqual(view.action.cget("text_color"), self.theme.on_accent)
                            self.assertInside(view.action._text_label, view.action)
                            self.assertInside(view.action._image_label, view.action)
                            callback.assert_not_called()
                            self.browser.assert_not_called()
                            view.action.invoke()
                            callback.assert_called_once_with()
                            self.browser.assert_not_called()
                            window.destroy()

        def test_source_or_unverified_release_does_not_promise_automatic_installation(self):
            callback = mock.Mock()
            _, view = self.sidebar(callback)
            with mock.patch.object(update_button.sys, "frozen", False):
                self.check_release(view, "99.0.0")
                self.assertEqual(view.action.cget("text"), "Release page")
            self.check_release(view, "99.0.0", include_asset=False)
            self.assertEqual(view.action.cget("text"), "Release page")
            view.action.invoke()
            callback.assert_called_once_with()

        def test_network_failure_removes_old_update_action_and_retry_succeeds(self):
            callback = mock.Mock()
            _, view = self.sidebar(callback)
            self.check_release(view, "99.0.0")
            self.assertTrue(view.action.winfo_ismapped())
            with mock.patch.object(update_check, "fetch_latest_release", side_effect=URLError("offline")):
                view.check()
                self.until(lambda: not view.task.running)
            self.assertEqual(view.status.cget("text"), "Could not reach GitHub. Please retry.")
            self.assertFalse(view.action.winfo_ismapped())
            self.assertFalse(update_check.get_status()["has_update"])
            self.assertEqual(view.button.cget("state"), "normal")
            view.open_update()
            callback.assert_not_called()
            self.check_release(view, __version__)
            self.assertEqual(view.status.cget("text"), "You are up to date")

        def test_unexpected_worker_error_remains_visible_and_can_be_retried(self):
            _, view = self.sidebar()
            self.check_release(view, "99.0.0")
            with mock.patch.object(update_check, "run_check", side_effect=RuntimeError("synthetic failure")):
                view.check()
                self.until(lambda: not view.task.running)
            view.refresh()
            self.assertEqual(view.status.cget("text"), "Could not reach GitHub. Please retry.")
            self.assertFalse(view.action.winfo_ismapped())
            self.assertEqual(view.button.cget("state"), "normal")
            self.check_release(view, __version__)
            self.assertEqual(view.status.cget("text"), "You are up to date")

        def test_missing_release_is_distinct_from_an_offline_github_check(self):
            _, view = self.sidebar()
            error = HTTPError(update_check.RELEASES_LATEST_API, 404, "Not Found", {}, None)
            with mock.patch.object(update_check, "fetch_latest_release", side_effect=error):
                view.check()
                self.until(lambda: not view.task.running)
            self.assertEqual(view.status.cget("text"), "No release found")
            self.assertFalse(view.action.winfo_ismapped())
            self.assertEqual(view.button.cget("state"), "normal")
            set_language("ru")
            view.refresh()
            self.assertEqual(view.status.cget("text"), "Релиз не найден")

        def test_language_change_updates_result_action_and_in_flight_labels(self):
            _, view = self.sidebar(mock.Mock())
            self.check_release(view, "99.0.0")
            set_language("ru")
            view.refresh()
            self.assertEqual(view.button.cget("text"), "Проверить\nобновления")
            self.assertEqual(view.status.cget("text"), "Доступна версия 99.0.0")
            self.assertEqual(view.action.cget("text"), "Обновить")
            entered, release = threading.Event(), threading.Event()

            def fetch():
                entered.set()
                release.wait(3)
                return {"tag_name": f"v{__version__}"}

            with mock.patch.object(update_check, "fetch_latest_release", side_effect=fetch):
                try:
                    view.check()
                    self.assertTrue(entered.wait(2))
                    set_language("en")
                    view.refresh()
                    self.assertEqual(view.button.cget("text"), t("dashboard.update_checking"))
                    self.assertEqual(view.status.cget("text"), t("dashboard.update_wait"))
                    self.assertFalse(view.action.winfo_ismapped())
                finally:
                    release.set()
                    self.until(lambda: not view.task.running)
            self.assertEqual(view.status.cget("text"), "You are up to date")

        def test_closing_window_cancels_pending_tk_poll_while_worker_finishes(self):
            callback = mock.Mock()
            window, view = self.sidebar(callback)
            entered, release, finished = threading.Event(), threading.Event(), threading.Event()
            real_run_check = update_check.run_check

            def fetch():
                entered.set()
                release.wait(3)
                return {"tag_name": "v99.0.0"}

            def run_check(version):
                try:
                    real_run_check(version)
                finally:
                    finished.set()

            with mock.patch.object(update_check, "fetch_latest_release", side_effect=fetch), \
                    mock.patch.object(update_check, "run_check", side_effect=run_check):
                try:
                    view.check()
                    self.assertTrue(entered.wait(2))
                    self.pump(60)
                    self.assertIsNotNone(view.task.pending)
                    window.destroy()
                    self.assertTrue(view.task.closed)
                    self.assertIsNone(view.task.pending)
                finally:
                    release.set()
                    self.assertTrue(finished.wait(2))
                    self.pump(100)
            view.refresh()
            view.check()
            view.open_update()
            callback.assert_not_called()
            self.browser.assert_not_called()
            self.assertFalse(self.errors)

        def test_manual_checks_work_with_startup_checks_disabled_at_minimum_dashboard_size(self):
            from ui.dashboard import build_dashboard
            from utils.default_config import default_tray_config
            from utils.live_logs import LiveLogHandler

            for language in ("ru", "en"):
                for appearance in ("light", "dark"):
                    with self.subTest(language=language, appearance=appearance):
                        set_language(language)
                        apply_ctk_appearance(self.ctk, appearance)
                        config = default_tray_config()
                        config.update(check_updates=False, language=language)
                        window = self.window("860x640")
                        callback = mock.Mock()
                        view = build_dashboard(
                            self.ctk, window, self.theme, config, running=lambda: False,
                            on_telegram=lambda: None, on_settings=lambda: None,
                            on_restart=lambda: None,
                            on_close=lambda: None, config_path="synthetic-config.json",
                            log_source=LiveLogHandler(), on_update=callback,
                        )
                        window.geometry("860x640+12000+12000")
                        window.deiconify()
                        self.pump(80)
                        self.check_release(view.updates, "99.0.0")
                        self.assertFalse(config["check_updates"])
                        for widget in (view.updates.frame, view.updates.button,
                                       view.updates.status, view.updates.action):
                            self.assertInside(widget, window)
                        self.assertInside(view.updates.button, view.updates.frame)
                        self.assertInside(view.updates.button._text_label, view.updates.button)
                        self.assertInside(view.updates.action._text_label, view.updates.action)
                        callback.assert_not_called()
                        self.browser.assert_not_called()
                        view.close()

        def test_background_download_shows_real_bytes_and_blocks_duplicate_actions(self):
            callback = mock.Mock()
            _, view = self.sidebar(callback)
            self.check_release(view, "99.0.0")
            entered, release, finished = threading.Event(), threading.Event(), threading.Event()
            runs, widget_threads = [], []
            ui_thread = threading.get_ident()

            def work():
                run = self.begin_download(total=4096, downloaded=1024)
                runs.append(run)
                entered.set()
                release.wait(3)
                update_progress.set_download(run, 4096, 4096)
                update_progress.set_phase(run, "verifying")
                finished.set()

            original_configure = view.progress_bar.configure

            def configure(*args, **kwargs):
                widget_threads.append(threading.get_ident())
                return original_configure(*args, **kwargs)

            worker = threading.Thread(target=work)
            with mock.patch.object(view.progress_bar, "configure", side_effect=configure), \
                    mock.patch.object(update_check, "run_check") as check:
                try:
                    worker.start()
                    self.assertTrue(entered.wait(2))
                    view.refresh()
                    self.pump()
                    self.assertEqual(view.progress_bar.cget("mode"), "determinate")
                    self.assertAlmostEqual(view.progress_bar.get(), 0.25)
                    self.assertIn("25%", view.progress_details.cget("text"))
                    self.assertIn("1.0KB / 4.0KB", view.progress_details.cget("text"))
                    self.assertEqual(view.status.cget("text"), t("dashboard.update_progress_downloading"))
                    self.assertEqual(view.button.cget("state"), "disabled")
                    self.assertEqual(view.action.cget("state"), "disabled")
                    self.assertFalse(view.action.winfo_ismapped())
                    view.button.invoke()
                    view.action.invoke()
                    view.check()
                    view.open_update()
                    check.assert_not_called()
                    callback.assert_not_called()
                    self.browser.assert_not_called()
                    release.set()
                    self.assertTrue(finished.wait(2))
                    view.refresh()
                    self.assertAlmostEqual(view.progress_bar.get(), 1)
                    self.assertEqual(view.status.cget("text"), t("dashboard.update_progress_verifying"))
                    self.assertIn("Downloaded 100%", view.progress_details.cget("text"))
                    self.assertNotIn("installed", view.status.cget("text").lower())
                    for phase in ("starting_installer", "restarting"):
                        update_progress.set_phase(runs[0], phase)
                        view.refresh()
                        self.assertEqual(view.status.cget("text"), t("dashboard.update_progress_" + phase))
                        self.assertTrue(view._animating)
                        self.assertEqual(view.button.cget("state"), "disabled")
                finally:
                    release.set()
                    worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertTrue(widget_threads)
            self.assertEqual(set(widget_threads), {ui_thread})

        def test_unknown_size_is_indeterminate_until_real_total_arrives(self):
            _, view = self.sidebar()
            run = self.begin_download(downloaded=8192)
            view.refresh()
            self.pump()
            self.assertEqual(view.progress_bar.cget("mode"), "indeterminate")
            self.assertTrue(view._animating)
            self.assertNotIn("%", view.progress_details.cget("text"))
            self.assertIn("8.0KB", view.progress_details.cget("text"))
            animation = view.progress_bar._loop_after_id
            update_progress.set_download(run, 8192, 16384)
            view.refresh()
            self.assertFalse(view._animating)
            self.assertEqual(view.progress_bar.cget("mode"), "determinate")
            self.assertAlmostEqual(view.progress_bar.get(), 0.5)
            self.assertIn("50%", view.progress_details.cget("text"))
            with self.assertRaises(TclError):
                self.app.tk.call("after", "info", animation)

        def test_failed_update_is_generic_retryable_and_recheck_clears_terminal_state(self):
            callback = mock.Mock()
            _, view = self.sidebar(callback)
            self.check_release(view, "99.0.0")
            run = self.begin_download(downloaded=1024)
            view.refresh()
            update_progress.fail(run)
            view.refresh()
            self.pump()
            self.assertEqual(view.status.cget("text"), t("dashboard.update_progress_failed"))
            self.assertFalse(view._animating)
            self.assertFalse(view.progress_frame.winfo_ismapped())
            self.assertEqual(view.button.cget("state"), "normal")
            self.assertEqual(view.action.cget("text"), t("dashboard.update_progress_retry"))
            self.assertTrue(view.action.winfo_ismapped())
            self.assertEqual(set(update_progress.get_progress()),
                             {"active", "phase", "downloaded", "total", "version"})
            view.action.invoke()
            callback.assert_called_once_with()
            self.check_release(view, __version__)
            self.assertEqual(update_progress.get_progress()["phase"], "idle")
            self.assertEqual(view.status.cget("text"), t("dashboard.update_current"))

        def test_close_stops_only_animation_and_reopen_reads_running_download(self):
            run = self.begin_download(downloaded=2048)
            window, view = self.sidebar()
            self.assertTrue(view._animating)
            animation = view.progress_bar._loop_after_id
            window.destroy()
            self.pump()
            self.assertTrue(view.task.closed)
            self.assertFalse(view._animating)
            self.assertTrue(update_progress.get_progress()["active"])
            with self.assertRaises(TclError):
                self.app.tk.call("after", "info", animation)
            worker = threading.Thread(target=lambda: update_progress.set_download(run, 7168, None))
            worker.start()
            worker.join(2)
            view.refresh()
            view.check()
            view.open_update()
            _, reopened = self.sidebar()
            self.assertEqual(reopened.source.cget("text"), REPOSITORY)
            self.assertTrue(reopened._animating)
            self.assertIn("7.0KB", reopened.progress_details.cget("text"))
            self.assertEqual(reopened.button.cget("state"), "disabled")
            self.assertTrue(update_progress.get_progress()["active"])

        def test_progress_fits_minimum_dashboard_and_keeps_refreshing_while_logs_visible(self):
            from ui.dashboard import build_dashboard
            from utils.default_config import default_tray_config
            from utils.live_logs import LiveLogHandler

            for language in ("ru", "en"):
                for appearance in ("light", "dark"):
                    with self.subTest(language=language, appearance=appearance):
                        set_language(language)
                        apply_ctk_appearance(self.ctk, appearance)
                        config = default_tray_config()
                        config.update(check_updates=False, language=language)
                        window = self.window("860x640")
                        run = self.begin_download(total=26 * 1024 * 1024, downloaded=13 * 1024 * 1024)
                        view = build_dashboard(
                            self.ctk, window, self.theme, config, running=lambda: False,
                            on_telegram=lambda: None, on_settings=lambda: None, on_restart=lambda: None,
                            on_close=lambda: None, config_path="synthetic-config.json",
                            log_source=LiveLogHandler(), on_update=mock.Mock(),
                        )
                        window.geometry("860x640+12000+12000")
                        window.deiconify()
                        self.pump(80)
                        try:
                            for phase in ("preparing", "downloading", "verifying", "starting_installer", "restarting"):
                                update_progress.set_phase(run, phase)
                                view.updates.refresh()
                                self.pump(20)
                                for widget in (view.updates.frame, view.updates.button, view.updates.status,
                                               view.updates.source, view.updates.progress_frame,
                                               view.updates.progress_bar, view.updates.progress_details):
                                    self.assertInside(widget, window)
                                self.assertInside(view.updates.status._label, view.updates.status)
                                self.assertInside(view.updates.progress_details._label, view.updates.progress_details)
                                self.assertEqual(len([child for child in view.updates.progress_frame.winfo_children()
                                                     if isinstance(child, self.ctk.CTkProgressBar)]), 1)
                            update_progress.set_phase(run, "downloading")
                            view.show_logs()
                            worker = threading.Thread(target=lambda: update_progress.set_download(
                                run, 19 * 1024 * 1024, 26 * 1024 * 1024))
                            worker.start()
                            worker.join(2)
                            self.until(lambda: view.updates.progress_bar.cget("mode") == "determinate"
                                       and view.updates.progress_bar.get() > 0.7)
                            self.assertTrue(view.logs_visible)
                            view.show_overview()
                            self.assertGreater(view.updates.progress_bar.get(), 0.7)
                            self.assertEqual(view.updates.source.cget("text"), REPOSITORY)
                        finally:
                            view.close()
                            update_progress.fail(run)
                            update_progress.clear_finished()


if __name__ == "__main__":
    if _NATIVE_MODE:
        sys.argv.remove("--native-run")
    unittest.main()
