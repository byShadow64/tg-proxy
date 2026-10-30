"""Cold-start races use real threads and a blocked synthetic CTk factory."""
import threading
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

from utils import tray_common as tray

_REAL_THREAD = threading.Thread


class FakeRoot:
    def __init__(self):
        self.stopped = threading.Event()
        self.withdrawn = threading.Event()
        self.destroyed = threading.Event()

    def withdraw(self):
        self.withdrawn.set()

    def mainloop(self):
        self.stopped.wait(3)

    def destroy(self):
        self.destroyed.set()

    def quit(self):
        self.stopped.set()


class CtkStartupTest(unittest.TestCase):
    def setUp(self):
        self.threads, self.roots = [], []
        self.release = threading.Event()
        self.calls = 0
        self.cleaning = False
        self.entered = threading.Condition()
        self.stack = self.enterContext(ExitStack())
        for name, value in (("_ctk_root", None), ("_ctk_root_ready", threading.Event()),
                            ("_ctk_root_lock", threading.Lock()), ("_ctk_root_thread", None)):
            self.stack.enter_context(mock.patch.object(tray, name, value, create=True))
        for name in ("install_tkinter_variable_del_guard", "apply_ctk_appearance", "install_window_icon"):
            self.stack.enter_context(mock.patch("ui.ctk_theme." + name))
        self.ctk = SimpleNamespace(CTk=self.factory)

    def tearDown(self):
        self.cleaning = True
        self.release.set()
        for root in self.roots:
            root.stopped.set()
        for thread in self.threads:
            thread.join(2)
            self.assertFalse(thread.is_alive(), "Synthetic CTk thread did not finish")

    def factory(self):
        with self.entered:
            self.calls += 1
            self.entered.notify_all()
        if not self.release.wait(2):
            raise TimeoutError("Synthetic root creation was not released")
        root = FakeRoot()
        self.roots.append(root)
        if self.cleaning:
            root.stopped.set()
        return root

    def tracked_thread(self, *args, **kwargs):
        thread = _REAL_THREAD(*args, **kwargs)
        self.threads.append(thread)
        start = thread.start

        def start_until_constructor_entered():
            with self.entered:
                expected = self.calls + 1
            start()
            with self.entered:
                self.assertTrue(self.entered.wait_for(lambda: self.calls >= expected, timeout=2))

        thread.start = start_until_constructor_entered
        return thread

    def test_repeated_requests_during_blocked_creation_start_only_one_root_thread(self):
        self.stack.enter_context(mock.patch.object(tray.threading, "Thread", side_effect=self.tracked_thread))
        # Collapse the five-second readiness timeout while keeping the root
        # constructor genuinely blocked in its own thread.
        wait = self.stack.enter_context(mock.patch.object(tray._ctk_root_ready, "wait", return_value=False))
        for _ in range(4):
            self.assertFalse(tray.ensure_ctk_thread(self.ctk))
        self.assertEqual(self.calls, 1)
        self.assertEqual(len(self.threads), 1)
        self.assertEqual(wait.call_args_list, [mock.call(timeout=5.0)] * 4)

    def test_partial_root_is_not_reported_ready_before_withdraw_finishes(self):
        root = FakeRoot()
        entered = threading.Event()

        def blocked_withdraw():
            entered.set()
            self.release.wait(2)
            root.withdrawn.set()

        root.withdraw = blocked_withdraw
        self.roots.append(root)
        self.ctk.CTk = mock.Mock(return_value=root)

        def thread_factory(*args, **kwargs):
            thread = _REAL_THREAD(*args, **kwargs)
            self.threads.append(thread)
            original = thread.start

            def start():
                original()
                self.assertTrue(entered.wait(2))

            thread.start = start
            return thread

        self.stack.enter_context(mock.patch.object(tray.threading, "Thread", side_effect=thread_factory))
        self.stack.enter_context(mock.patch.object(tray._ctk_root_ready, "wait", return_value=False))
        self.assertFalse(tray.ensure_ctk_thread(self.ctk))
        self.assertIsNone(tray._ctk_root)
        self.assertFalse(tray._ctk_root_ready.is_set())

    def test_simultaneous_callers_share_one_ready_root(self):
        self.stack.enter_context(mock.patch.object(tray.threading, "Thread", side_effect=self.tracked_thread))
        original_wait = tray._ctk_root_ready.wait
        waiters = threading.Condition()
        count = 0

        def wait(timeout):
            nonlocal count
            self.assertEqual(timeout, 5.0)
            with waiters:
                count += 1
                waiters.notify_all()
            return original_wait(2)

        self.stack.enter_context(mock.patch.object(tray._ctk_root_ready, "wait", side_effect=wait))
        outcomes = []
        callers = [_REAL_THREAD(target=lambda: outcomes.append(tray.ensure_ctk_thread(self.ctk)))
                   for _ in range(6)]
        for caller in callers:
            caller.start()
        try:
            with waiters:
                self.assertTrue(waiters.wait_for(lambda: count == len(callers), timeout=2))
            self.assertEqual(self.calls, 1)
            self.assertEqual(len(self.threads), 1)
            self.assertIsNone(tray._ctk_root)
        finally:
            self.release.set()
            for caller in callers:
                caller.join(2)
                self.assertFalse(caller.is_alive())
        self.assertEqual(outcomes, [True] * len(callers))

    def test_successful_initialization_is_reused_and_failure_can_be_retried(self):
        self.release.set()
        root = FakeRoot()
        self.roots.append(root)
        factory = mock.Mock(side_effect=[RuntimeError("Synthetic CTk failure"), root])
        self.ctk.CTk = factory

        def threads(*args, **kwargs):
            thread = _REAL_THREAD(*args, **kwargs)
            self.threads.append(thread)
            return thread

        self.stack.enter_context(mock.patch.object(tray.threading, "Thread", side_effect=threads))
        self.assertFalse(tray.ensure_ctk_thread(self.ctk))
        self.threads[0].join(1)
        self.assertFalse(self.threads[0].is_alive())
        self.assertTrue(tray.ensure_ctk_thread(self.ctk))
        self.assertTrue(root.withdrawn.is_set())
        self.assertIs(tray._ctk_root, root)
        self.assertTrue(tray.ensure_ctk_thread(self.ctk, "dark"))
        self.assertEqual(factory.call_count, 2)
        self.assertEqual(len(self.threads), 2)

    def test_missing_ctk_does_not_start_a_thread(self):
        with mock.patch.object(tray.threading, "Thread") as thread:
            self.assertFalse(tray.ensure_ctk_thread(None))
        thread.assert_not_called()

    def test_thread_start_failure_allows_another_initialization_attempt(self):
        self.release.set()
        failed = mock.Mock()
        failed.start.side_effect = RuntimeError("Synthetic thread start failure")
        attempts = 0

        def threads(*args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return failed
            thread = _REAL_THREAD(*args, **kwargs)
            self.threads.append(thread)
            return thread

        self.stack.enter_context(mock.patch.object(tray.threading, "Thread", side_effect=threads))
        self.assertFalse(tray.ensure_ctk_thread(self.ctk))
        self.assertIsNone(tray._ctk_root)
        self.assertTrue(tray.ensure_ctk_thread(self.ctk))
        self.assertEqual(attempts, 2)

    def test_failed_setup_destroys_partial_root_before_retry(self):
        self.release.set()

        def threads(*args, **kwargs):
            thread = _REAL_THREAD(*args, **kwargs)
            self.threads.append(thread)
            return thread

        self.stack.enter_context(mock.patch.object(tray.threading, "Thread", side_effect=threads))
        self.stack.enter_context(mock.patch("ui.ctk_theme.install_window_icon",
                                          side_effect=[RuntimeError("Synthetic setup failure"), None]))
        self.assertFalse(tray.ensure_ctk_thread(self.ctk))
        self.assertTrue(self.roots[0].destroyed.is_set())
        self.assertIsNone(tray._ctk_root)
        self.assertTrue(tray.ensure_ctk_thread(self.ctk))
        self.assertEqual(len(self.roots), 2)

    def test_finished_mainloop_clears_stale_root_and_can_start_again(self):
        self.release.set()

        def threads(*args, **kwargs):
            thread = _REAL_THREAD(*args, **kwargs)
            self.threads.append(thread)
            return thread

        self.stack.enter_context(mock.patch.object(tray.threading, "Thread", side_effect=threads))
        self.assertTrue(tray.ensure_ctk_thread(self.ctk))
        old = self.roots[0]
        old.stopped.set()
        self.threads[0].join(2)
        self.assertFalse(self.threads[0].is_alive())
        self.assertTrue(old.destroyed.is_set())
        self.assertIsNone(tray._ctk_root)
        self.assertTrue(tray.ensure_ctk_thread(self.ctk))
        self.assertIsNot(tray._ctk_root, old)


if __name__ == "__main__":
    unittest.main()
