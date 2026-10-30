"""Native CTk checks for diagnosis cancellation, privacy and view lifecycle."""
import copy
import subprocess
import sys
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from tkinter import TclError

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ui.ctk_theme import apply_ctk_appearance, ctk_theme_for_platform
from ui.connection_diagnostics import _outcome_key, _result_counts
from proxy import __version__
from ui.dashboard import build_dashboard
from ui.i18n import get_config_language, set_language, t
from utils import connection_diagnostics as diagnostics
from utils import update_check
from utils.live_logs import LiveLogHandler

_NATIVE_MODE = "--native-run" in sys.argv


def result(kind="local", status="ok", error_code="", *, label="Local", dc=None, media=False):
    return SimpleNamespace(kind=kind, label=label, dc=dc, media=media, status=status,
                           error_code=error_code, setup_ms=12 if status == "ok" else None)


def report(results=(), status="complete", recommendation="open_routes"):
    return SimpleNamespace(results=tuple(results), status=status, recommendation=recommendation,
                           started_at="2026-10-24T19:00:00Z", version="test", duration_ms=35,
                           coverage=())


class DiagnosticsOutcomeTest(unittest.TestCase):
    def test_counts_keep_unconfirmed_protocols_separate_from_skips_and_failures(self):
        rows = (result(), result("cf"), result("direct", "error", "tls"),
                result("h2", "skipped", "h2_unconfirmed"),
                result("helper", "skipped", "legacy_unconfirmed"),
                result("tcp", "skipped", "tcp_unconfirmed"),
                result("worker", "incomplete", "deadline"),
                result("cf", "skipped", "disabled"), result("helper", "cancelled", "cancelled"))
        self.assertEqual(_result_counts(rows),
                         dict(ok=2, error=1, unconfirmed=4, skipped=1, cancelled=1))
        self.assertEqual(sum(_result_counts(rows).values()), len(rows))

    def test_local_success_alone_does_not_confirm_a_transport_or_hide_failures(self):
        self.assertEqual(_outcome_key((result(),), "complete"), "partial")
        self.assertEqual(_outcome_key((result(), result("direct", "error", "tls")), "complete"),
                         "issues")
        self.assertEqual(_outcome_key((result("local", "error", "refused"), result("cf")), "complete"),
                         "local_unavailable")

    def test_successful_alternative_and_incomplete_scope_remain_explicit(self):
        self.assertEqual(_outcome_key((result(), result("direct", "error", "tls"), result("cf")),
                                     "complete"), "available_with_errors")
        self.assertEqual(_outcome_key((result(), result("cf")), "partial"), "partial_available")
        self.assertEqual(_outcome_key((result("cf"), result("tcp", "skipped", "tcp_unconfirmed")),
                                     "complete"), "partial_available")
        self.assertEqual(_outcome_key((result(), result("cf")), "complete"), "available")


if not _NATIVE_MODE:
    class ConnectionDiagnosticsProcessTest(unittest.TestCase):
        def test_native_connection_diagnostics(self):
            process = subprocess.run(
                [sys.executable, "-B", str(Path(__file__).resolve()), "--native-run"],
                capture_output=True, text=True, timeout=50,
            )
            if "NATIVE_DISPLAY_UNAVAILABLE" in process.stdout:
                self.skipTest("Native Tk display is unavailable")
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)


if _NATIVE_MODE:
    class NativeConnectionDiagnosticsTest(unittest.TestCase):
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
            self.views, self.errors = [], []
            self.app.report_callback_exception = lambda *args: self.errors.append(args)
            self.addCleanup(set_language, get_config_language())
            self.addCleanup(self.ctk.set_appearance_mode, self.ctk.get_appearance_mode())
            set_language("en")
            apply_ctk_appearance(self.ctk, "light")
            self.stack = ExitStack()
            self.addCleanup(self.stack.close)
            self.network = self.stack.enter_context(mock.patch.object(
                update_check, "fetch_latest_release", side_effect=AssertionError("Real network is forbidden")))

        def tearDown(self):
            for view in self.views:
                if not view.closed:
                    view.close()
            self.app.update()
            self.network.assert_not_called()
            self.assertFalse(self.errors)

        def pump(self, milliseconds=20):
            ready = self.ctk.BooleanVar(master=self.app, value=False)
            self.app.after(milliseconds, lambda: ready.set(True))
            self.app.wait_variable(ready)
            self.app.update()

        def until(self, predicate, timeout=3):
            deadline = time.monotonic() + timeout
            while not predicate():
                if time.monotonic() >= deadline:
                    self.fail("Connection check did not reach expected UI state")
                self.pump()

        def view(self, state=None):
            state = state if state is not None else {"alive": True, "identity": "original"}
            config = {"host": "127.0.0.1", "port": 1443, "helper_enabled": False,
                      "secret": "synthetic-private-secret", "helper_token": "synthetic-token"}
            root = self.ctk.CTkToplevel(self.app)
            root.withdraw()
            callbacks = SimpleNamespace(restart=mock.Mock(), routes=mock.Mock(), telegram=mock.Mock())
            view = build_dashboard(
                self.ctk, root, ctk_theme_for_platform(), config,
                running=lambda: state["alive"], on_telegram=callbacks.telegram,
                on_settings=lambda: None, on_routes=callbacks.routes,
                on_restart=callbacks.restart, on_close=lambda: None,
                config_path="synthetic-config.json", log_source=LiveLogHandler(),
                get_diagnostics_snapshot=lambda: SimpleNamespace(identity=state["identity"]),
            )
            self.views.append(view)
            root.geometry("860x640+12000+12000")
            root.deiconify()
            self.pump(80)
            self.assertEqual(root.title(), t("dashboard.title") + (" [Staging]" if "-staging." in __version__ else ""))
            return view, callbacks, config

        def test_progress_cancel_retry_and_logs_navigation_are_non_blocking(self):
            entered = threading.Event()
            ids = []
            local = result()

            def work(snapshot, cancel, emit):
                ids.append(threading.get_ident())
                entered.set()
                emit({"kind": "progress", "result": local, "completed": 1, "total": 2})
                cancel.wait(3)
                return report((local,), status="cancelled", recommendation="retry")

            worker = self.stack.enter_context(mock.patch.object(diagnostics, "run_diagnostics", side_effect=work))
            view, callbacks, config = self.view()
            original = copy.deepcopy(config)
            card = view.connection_diagnostics
            card.check_button.invoke()
            self.assertTrue(entered.wait(2))
            self.until(lambda: card.completed == 1)
            self.assertNotEqual(ids, [threading.get_ident()])
            self.assertEqual(card.check_button.cget("state"), "disabled")
            card.start()
            card.check_button.invoke()
            worker.assert_called_once()
            responsive = []
            self.app.after(0, lambda: responsive.append(True))
            view.show_logs()
            self.pump(50)
            self.assertEqual(responsive, [True])
            self.assertFalse(card._cancel.is_set())
            view.show_overview()
            set_language("ru")
            view.refresh()
            self.assertEqual(card.title.cget("text"), t("connection_diagnostics.title"))
            card.cancel_button.invoke()
            self.assertTrue(card._cancel.is_set())
            self.until(lambda: not card.checking)
            self.assertEqual(card.report.status, "cancelled")
            self.assertEqual(card.check_button.cget("state"), "normal")
            worker.side_effect = None
            worker.return_value = report((local, result("direct", dc=2)))
            card.start()
            self.until(lambda: not card.checking)
            self.assertEqual(worker.call_count, 2)
            card.action_button.invoke()
            callbacks.routes.assert_called_once_with()
            callbacks.restart.assert_not_called()
            self.assertEqual(config, original)

        def test_configuration_change_cancels_and_late_results_do_not_replace_new_check(self):
            release, entered = threading.Event(), threading.Event()

            def work(snapshot, cancel, emit):
                entered.set()
                release.wait(3)
                emit({"kind": "progress", "result": result("direct"), "completed": 1, "total": 1})
                return report((result("direct"),))

            worker = self.stack.enter_context(mock.patch.object(diagnostics, "run_diagnostics", side_effect=work))
            state = {"alive": True, "identity": "first"}
            view, callbacks, _ = self.view(state)
            card = view.connection_diagnostics
            try:
                card.start()
                self.assertTrue(entered.wait(2))
                old_id = card._run_id
                state["identity"] = "changed"
                view.refresh()
                self.assertTrue(card.stale)
                self.assertTrue(card._cancel.is_set())
                self.assertEqual(card.copy_button.cget("state"), "disabled")
                card.act()
                callbacks.routes.assert_not_called()
            finally:
                release.set()
            self.until(lambda: not card.checking)
            self.assertIsNone(card.report)
            self.assertEqual(card.results, [])
            worker.side_effect = None
            expected = report((result(),), recommendation="retry")
            worker.return_value = expected
            card.start()
            self.until(lambda: card.report is expected)
            card._queue.put((old_id, "done", report((result("helper"),))))
            card._poll()
            self.assertIs(card.report, expected)
            self.assertFalse(card.stale)

        def test_close_sets_cancel_and_does_not_wait_for_worker_or_touch_closed_widgets(self):
            entered, release, exited = threading.Event(), threading.Event(), threading.Event()

            def work(snapshot, cancel, emit):
                entered.set()
                try:
                    release.wait(3)
                    emit({"kind": "progress", "result": result(), "completed": 1, "total": 1})
                    return report((result(),))
                finally:
                    exited.set()

            self.stack.enter_context(mock.patch.object(diagnostics, "run_diagnostics", side_effect=work))
            view, _, _ = self.view()
            card = view.connection_diagnostics
            try:
                card.start()
                self.assertTrue(entered.wait(2))
                started = time.monotonic()
                view.close()
                self.assertLess(time.monotonic() - started, 0.4)
                self.assertTrue(card.closed)
                self.assertTrue(card._cancel.is_set())
                self.assertIsNone(card._pending)
            finally:
                release.set()
            self.assertTrue(exited.wait(2))
            self.pump(100)
            self.assertIsNone(card.report)

        def test_copy_actions_theme_layout_and_safe_error_rendering(self):
            output = report((result(), result("helper", "error", "tls")), recommendation="open_routes")
            worker = self.stack.enter_context(mock.patch.object(diagnostics, "run_diagnostics", return_value=output))
            formatter = self.stack.enter_context(mock.patch.object(
                diagnostics, "format_report", return_value="Safe support report\nTLS verification failed"))
            state = {"alive": True, "identity": "unchanged"}
            view, callbacks, config = self.view(state)
            card = view.connection_diagnostics
            original = copy.deepcopy(config)
            card.copy_report()
            formatter.assert_not_called()
            card.start()
            self.until(lambda: not card.checking)
            self.assertIn(t("connection_diagnostics.error.tls"), card.result_text.get("1.0", "end"))
            self.assertNotIn(config["secret"], card.result_text.get("1.0", "end"))
            card.copy_button.invoke()
            formatter.assert_called_once_with(output)
            self.assertEqual(view.root.clipboard_get(), "Safe support report\nTLS verification failed")
            self.assertEqual(card.copy_button.cget("text"), t("connection_diagnostics.copied"))
            for appearance in ("light", "dark"):
                apply_ctk_appearance(self.ctk, appearance)
                for language in ("ru", "en"):
                    set_language(language)
                    view.refresh()
                    self.pump(40)
                    for widget in (card.title, card.hint, card.summary, card.result_text, card.advice):
                        self.assertLessEqual(widget.winfo_x() + widget.winfo_width(), card.frame.winfo_width() + 1)
                    self.assertLessEqual(view.endpoint.master.winfo_rootx() + view.endpoint.master.winfo_width(),
                                         view.overview._parent_canvas.winfo_rootx() +
                                         view.overview._parent_canvas.winfo_width() + 1)
                    self.assertEqual(card.title.cget("text"), t("connection_diagnostics.title"))
            card.report = report((result(),), recommendation="start_proxy")
            card.act()
            callbacks.restart.assert_not_called()
            state["alive"] = False
            card.act()
            callbacks.restart.assert_called_once_with()
            self.assertEqual(config, original)
            worker.assert_called_once()

        def test_partial_coverage_is_explicit_and_custom_candidates_use_safe_indices(self):
            candidate = result("cf", label="private.example?token=secret DC2", dc=2, media=None)
            candidate.candidate_index = 2
            output = report((result(), candidate,
                             result("h2", "incomplete", "h2_unconfirmed")), status="partial")
            output.coverage = (SimpleNamespace(kind="cf", tested=3, total=20),)
            self.stack.enter_context(mock.patch.object(diagnostics, "run_diagnostics", return_value=output))
            view, _, _ = self.view()
            card = view.connection_diagnostics
            card.start()
            self.until(lambda: not card.checking)
            self.assertEqual(card.summary.cget("text"), t("connection_diagnostics.partial_available") +
                             "\n" + t("connection_diagnostics.counts", ok=2, error=0,
                                      unconfirmed=1, skipped=0, cancelled=0))
            self.assertEqual(card.coverage.cget("text"), t("connection_diagnostics.coverage",
                             kind=t("connection_diagnostics.kind.cf"), tested=3, total=20))
            rendered = card.result_text.get("1.0", "end")
            self.assertIn("#2", rendered)
            self.assertNotIn("private.example", rendered)
            self.assertNotIn("secret", rendered)
            self.assertNotIn(t("connection_diagnostics.messages"), rendered)

        def test_scope_summary_and_terminal_states_in_both_languages_and_themes(self):
            mixed = (result(), result("direct", "error", "tls"), result("cf"),
                     result("h2", "skipped", "h2_unconfirmed"),
                     result("worker", "skipped", "disabled"), result("helper", "cancelled", "cancelled"))
            for language in ("ru", "en"):
                for appearance in ("light", "dark"):
                    with self.subTest(language=language, appearance=appearance):
                        set_language(language)
                        apply_ctk_appearance(self.ctk, appearance)
                        view, _, _ = self.view()
                        card = view.connection_diagnostics
                        self.assertIsNone(card._identity)
                        self.assertIn(t("connection_diagnostics.scope", limit=3), card.hint.cget("text"))
                        self.assertFalse(card.result_text.winfo_ismapped())
                        card._identity = "original"
                        card.results = list(mixed)
                        card.report = report(mixed)
                        card._render()
                        self.pump(30)
                        counts = t("connection_diagnostics.counts", ok=2, error=1,
                                   unconfirmed=1, skipped=1, cancelled=1)
                        self.assertEqual(card.summary.cget("text"),
                                         t("connection_diagnostics.available_with_errors") + "\n" + counts)
                        self.assertNotIn(t("connection_diagnostics.issues"), card.summary.cget("text"))
                        self.assertNotIn("synthetic", card.summary.cget("text"))
                        for widget in (card.hint, card.summary, card.result_text):
                            self.assertGreaterEqual(widget.winfo_x(), 0)
                            self.assertLessEqual(widget.winfo_x() + widget.winfo_width(),
                                                 card.frame.winfo_width() + 1)
                        self.assertEqual(view.root.winfo_width(), 860)
                        self.assertEqual(view.root.winfo_height(), 640)
                        local_failure = (result("local", "error", "refused"), result("cf"))
                        card.results = list(local_failure)
                        card.report = report(local_failure)
                        card._render()
                        self.pump(20)
                        self.assertTrue(card.summary.cget("text").startswith(
                            t("connection_diagnostics.local_unavailable")))
                        self.assertEqual(card.summary.cget("text_color"), card.theme.danger)
                        self.assertLessEqual(card.summary.winfo_x() + card.summary.winfo_width(),
                                             card.frame.winfo_width() + 1)
                        card.results = list(mixed)
                        card.report = report(mixed)
                        card.report.status = "cancelled"
                        card._render()
                        self.assertEqual(card.summary.cget("text"),
                                         t("connection_diagnostics.cancelled") + "\n" + counts)
                        card.stale = True
                        card.report = None
                        card._render()
                        self.assertEqual(card.summary.cget("text"), t("connection_diagnostics.stale"))
                        self.assertEqual(card.copy_button.cget("state"), "disabled")
                        view.close()

        def test_live_results_preserve_reading_position_follow_tail_and_wait_for_cancel_cleanup(self):
            for language in ("ru", "en"):
                for appearance in ("light", "dark"):
                    with self.subTest(language=language, appearance=appearance):
                        set_language(language)
                        apply_ctk_appearance(self.ctk, appearance)
                        first, second, cleanup, finish = (threading.Event() for _ in range(4))
                        initial = [result("direct", dc=2, media=bool(index % 2)) for index in range(100)]

                        def work(snapshot, cancel, emit):
                            rows = list(initial)
                            for completed, row in enumerate(rows, 1):
                                emit(dict(kind="progress", result=row, completed=completed, total=103))
                            # These are explicit phases, not timed progression: a
                            # busy native renderer must not skip the 100-result
                            # phase merely because its worker wait expired.
                            if not first.wait(10):
                                raise AssertionError("Fixture's first phase was not released")
                            rows.append(result("cf", "error", "tls", dc=2))
                            emit(dict(kind="progress", result=rows[-1], completed=101, total=103))
                            if not second.wait(10):
                                raise AssertionError("Fixture's second phase was not released")
                            rows.append(result("worker", dc=4))
                            emit(dict(kind="progress", result=rows[-1], completed=102, total=103))
                            if not cancel.wait(10):
                                raise AssertionError("Fixture did not receive cancellation")
                            cleanup.set()
                            if not finish.wait(10):
                                raise AssertionError("Fixture cleanup phase was not released")
                            rows.append(result("helper", "cancelled", "cancelled"))
                            emit(dict(kind="progress", result=rows[-1], completed=103, total=103))
                            return report(rows, status="cancelled", recommendation="retry")

                        worker = self.stack.enter_context(mock.patch.object(
                            diagnostics, "run_diagnostics", side_effect=work))
                        view, _, _ = self.view()
                        card = view.connection_diagnostics
                        try:
                            card.start()
                            self.until(lambda: card.completed == 100)
                            inner, outer = card.result_text._textbox, view.overview._parent_canvas
                            inner.yview_moveto(.4)
                            outer.yview_moveto(.25)
                            self.pump()
                            anchor, outer_before = inner.index("@0,0"), outer.yview()
                            first.set()
                            self.until(lambda: card.completed == 101)
                            self.assertEqual(inner.index("@0,0"), anchor)
                            self.assert_same_yview(outer_before, outer.yview())
                            card._render()  # Repeated render without new data must be inert.
                            self.assertEqual(inner.index("@0,0"), anchor)
                            # Language/theme rebuilds keep the same result line in view.
                            set_language("en" if language == "ru" else "ru")
                            apply_ctk_appearance(self.ctk, "dark" if appearance == "light" else "light")
                            card.refresh()
                            self.pump()
                            self.assertEqual(inner.index("@0,0").split(".")[0], anchor.split(".")[0])
                            inner.see("end")
                            self.pump()
                            second.set()
                            self.until(lambda: card.completed == 102)
                            self.assertGreaterEqual(inner.yview()[1], .999)
                            inner.yview_moveto(.4)
                            self.pump()
                            anchor = inner.index("@0,0")
                            card.cancel()
                            self.assertTrue(cleanup.wait(2))
                            self.pump()
                            self.assertTrue(card.checking)
                            self.assertTrue(card._cancelling)
                            self.assertIn(t("connection_diagnostics.cancelling"), card.summary.cget("text"))
                            self.assertEqual(card.check_button.cget("state"), "disabled")
                            self.assertEqual(card.cancel_button.cget("state"), "disabled")
                            self.assertEqual(inner.index("@0,0"), anchor)
                            finish.set()
                            self.until(lambda: not card.checking)
                            self.assertIn(t("connection_diagnostics.cancelled"), card.summary.cget("text"))
                            self.assertEqual(inner.index("@0,0"), anchor)
                            self.assertEqual(card.check_button.cget("state"), "normal")
                            worker.side_effect = None
                            worker.return_value = report((result(), result("cf")))
                            card.start()
                            self.until(lambda: not card.checking)
                            self.assertEqual(len(card.results), 2)
                            self.assertGreaterEqual(inner.yview()[1], .999)
                            self.assertIn(t("connection_diagnostics.available"), card.summary.cget("text"))
                        finally:
                            first.set()
                            second.set()
                            finish.set()
                            card.cancel()
                            self.until(lambda: not card.checking)
                            view.close()

        def test_unexpected_worker_failure_allows_retry_without_exception_disclosure(self):
            worker = self.stack.enter_context(mock.patch.object(
                diagnostics, "run_diagnostics", side_effect=RuntimeError("private-token-and-address")))
            view, _, _ = self.view()
            card = view.connection_diagnostics
            card.start()
            self.until(lambda: not card.checking)
            self.assertEqual(card.summary.cget("text"), t("connection_diagnostics.failed"))
            self.assertNotIn("private-token", card.summary.cget("text"))
            self.assertEqual(card.check_button.cget("state"), "normal")
            worker.side_effect = None
            worker.return_value = report((result(),), recommendation="retry")
            card.start()
            self.until(lambda: not card.checking)
            self.assertIsNotNone(card.report)

        def scrolling_card(self):
            view, _, _ = self.view()
            card = view.connection_diagnostics
            card._identity = "original"
            card.results = [result("direct", dc=2, media=bool(index % 2)) for index in range(100)]
            card.report = report(card.results)
            card._render()
            self.pump(60)
            outer = view.overview._parent_canvas
            inner = card.result_text._textbox
            outer.yview_moveto(0.25)
            inner.yview_moveto(0.4)
            self.pump(30)
            self.assertGreater(outer.yview()[0], 0)
            self.assertLess(outer.yview()[1], 1)
            self.assertGreater(inner.yview()[0], 0)
            self.assertLess(inner.yview()[1], 1)
            return view, card, inner, outer

        def assert_same_yview(self, expected, actual):
            for before, after in zip(expected, actual):
                self.assertAlmostEqual(before, after, places=7)

        def wheel(self, widget, delta):
            widget.event_generate("<MouseWheel>", delta=delta, x=4, y=4)
            self.pump(25)

        def test_wheel_over_results_scrolls_only_results_in_both_directions_and_at_boundaries(self):
            _, _, inner, outer = self.scrolling_card()
            for delta in (-120, 120):
                with self.subTest(delta=delta):
                    inner.yview_moveto(0.4)
                    outer.yview_moveto(0.25)
                    self.pump()
                    inner_before, outer_before = inner.yview(), outer.yview()
                    self.wheel(inner, delta)
                    if delta < 0:
                        self.assertGreater(inner.yview()[0], inner_before[0])
                    else:
                        self.assertLess(inner.yview()[0], inner_before[0])
                    self.assert_same_yview(outer_before, outer.yview())
            for edge, delta in ((0, 120), (1, -120)):
                with self.subTest(edge=edge):
                    inner.yview_moveto(edge)
                    outer.yview_moveto(0.25)
                    self.pump()
                    inner_before, outer_before = inner.yview(), outer.yview()
                    self.wheel(inner, delta)
                    self.assert_same_yview(inner_before, inner.yview())
                    self.assert_same_yview(outer_before, outer.yview())

        def test_wheel_over_result_scrollbar_is_contained_and_outside_still_scrolls_overview(self):
            _, card, inner, outer = self.scrolling_card()
            scrollbar = card.result_text._y_scrollbar._canvas
            for delta in (-120, 120):
                with self.subTest(delta=delta):
                    inner.yview_moveto(0.4)
                    outer.yview_moveto(0.25)
                    self.pump()
                    inner_before, outer_before = inner.yview(), outer.yview()
                    self.wheel(scrollbar, delta)
                    self.assertNotEqual(inner_before, inner.yview())
                    self.assert_same_yview(outer_before, outer.yview())
            for edge, delta in ((0, 120), (1, -120)):
                with self.subTest(scrollbar_edge=edge):
                    inner.yview_moveto(edge)
                    outer.yview_moveto(0.25)
                    self.pump()
                    inner_before, outer_before = inner.yview(), outer.yview()
                    self.wheel(scrollbar, delta)
                    self.assert_same_yview(inner_before, inner.yview())
                    self.assert_same_yview(outer_before, outer.yview())
            for delta in (-120, 120):
                with self.subTest(outside_delta=delta):
                    outer.yview_moveto(0.25)
                    self.pump()
                    outer_before, inner_before = outer.yview(), inner.yview()
                    self.wheel(card.hint._label, delta)
                    self.assertNotEqual(outer_before, outer.yview())
                    self.assert_same_yview(inner_before, inner.yview())

        def test_wheel_containment_survives_navigation_and_reopen_without_global_binding_leaks(self):
            for reopen in range(2):
                with self.subTest(reopen=reopen):
                    view, _, inner, outer = self.scrolling_card()
                    try:
                        for _ in range(3):
                            view.show_logs()
                            self.pump()
                            view.show_overview()
                            self.pump()
                        inner.yview_moveto(0.4)
                        outer.yview_moveto(0.25)
                        self.pump()
                        outer_before, inner_before = outer.yview(), inner.yview()
                        self.wheel(inner, -120)
                        self.assertGreater(inner.yview()[0], inner_before[0])
                        self.assert_same_yview(outer_before, outer.yview())
                    finally:
                        view.close()
                        self.pump()
            other_root = self.ctk.CTkToplevel(self.app)
            other_root.geometry("400x300+12000+12000")
            other = self.ctk.CTkTextbox(other_root, width=350, height=220)
            other.pack(fill="both", expand=True)
            other.insert("1.0", "\n".join(f"Ordinary text line {index}" for index in range(100)))
            try:
                self.pump(80)
                other._textbox.yview_moveto(0.4)
                self.pump()
                before = other._textbox.yview()
                self.wheel(other._textbox, -120)
                self.assertGreater(other._textbox.yview()[0], before[0])
            finally:
                other_root.destroy()


if __name__ == "__main__":
    sys.argv = [arg for arg in sys.argv if arg != "--native-run"]
    unittest.main()
