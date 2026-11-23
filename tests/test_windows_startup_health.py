"""Listener readiness controls the unchanged installer ACK; no production profile is used."""
import sys
import threading
import time
import unittest
from contextlib import ExitStack
from unittest.mock import patch


@unittest.skipUnless(sys.platform == "win32", "Windows startup health")
class StartupHealthTest(unittest.TestCase):
    def setUp(self):
        import windows
        self.app = windows
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(windows, "_startup_ack_thread", None))
        self.stack.enter_context(patch.object(windows, "_exiting", False))
        self.pending = self.stack.enter_context(patch.object(windows, "update_ack_pending", return_value=True))
        self.ack = self.stack.enter_context(patch.object(windows, "acknowledge_update"))

    def test_observer_waits_off_ui_thread_and_acknowledges_only_after_listener_ready(self):
        ready = threading.Event(); caller = threading.get_ident(); threads = []
        self.ack.side_effect = lambda: threads.append(threading.get_ident())
        with patch.object(self.app, "proxy_listener_ready", side_effect=ready.is_set), \
                patch.object(self.app, "proxy_running", return_value=True):
            started = time.monotonic()
            worker = self.app._acknowledge_when_proxy_ready()
            self.assertLess(time.monotonic() - started, .2)
            self.ack.assert_not_called()
            self.assertIs(self.app._acknowledge_when_proxy_ready(), worker)
            ready.set(); worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.ack.assert_called_once_with()
        self.assertNotEqual(threads, [caller])

    def test_dead_worker_or_stuck_listener_withholds_ack_for_existing_rollback(self):
        for alive in (False, True):
            with self.subTest(alive=alive), patch.object(self.app, "proxy_listener_ready", return_value=False), \
                    patch.object(self.app, "proxy_running", return_value=alive), \
                    patch.object(self.app, "STARTUP_ACK_TIMEOUT", .05):
                worker = self.app._acknowledge_when_proxy_ready(); worker.join(timeout=2)
                self.assertFalse(worker.is_alive())
                self.ack.assert_not_called()

    def test_normal_nonupdate_start_does_not_create_a_worker(self):
        self.pending.return_value = False
        self.assertIsNone(self.app._acknowledge_when_proxy_ready())
        self.ack.assert_not_called()
