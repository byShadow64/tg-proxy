import ctypes
import os
import subprocess
import sys
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from utils import windows_activation as activation


def event_name():
    return "Local\\TGProxyActivationTest_" + uuid.uuid4().hex


@unittest.skipUnless(sys.platform == "win32", "Native Windows events")
class NativeActivationTest(unittest.TestCase):
    def child_request(self, name, timeout=2):
        code = ("import sys; from utils.windows_activation import request_activation; "
                "raise SystemExit(0 if request_activation(sys.argv[1], float(sys.argv[2])) else 3)")
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.Popen([sys._base_executable, "-B", "-c", code, name, str(timeout)],
            cwd=str(Path(__file__).resolve().parents[1]), env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def assert_child_ok(self, child):
        stdout, stderr = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, (stdout, stderr))

    def test_native_cross_process_signal_before_start_is_retained_once(self):
        name = event_name()
        channel = activation.InstanceActivation.create(name)
        called = threading.Event()
        calls = []
        try:
            self.assert_child_ok(self.child_request(name))
            # Repeated pre-ready requests coalesce to one pending bit.
            for _ in range(4):
                self.assertTrue(activation.request_activation(name, timeout=0))
            self.assertFalse(called.is_set())
            channel.start(lambda: (calls.append(True), called.set()))
            self.assertTrue(called.wait(1))
            time.sleep(.1)
            self.assertEqual(calls, [True])
        finally:
            channel.close()
        self.assertFalse(activation.request_activation(name, timeout=0))

    def test_native_request_retries_before_owner_creation(self):
        name = event_name()
        child = self.child_request(name, 2)
        channel = None
        try:
            time.sleep(.15)
            channel = activation.InstanceActivation(name)
            self.assert_child_ok(child)
            called = threading.Event()
            channel.start(called.set)
            self.assertTrue(called.wait(1))
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=2)
            if channel is not None:
                channel.close()

    def test_native_concurrent_signals_coalesce_while_callback_is_busy(self):
        name = event_name()
        channel = activation.InstanceActivation(name)
        entered, release, second = threading.Event(), threading.Event(), threading.Event()
        calls = []
        def callback():
            calls.append(True)
            if len(calls) == 1:
                entered.set()
                release.wait(2)
            else:
                second.set()
        try:
            channel.start(callback)
            self.assertTrue(activation.request_activation(name, 0))
            self.assertTrue(entered.wait(1))
            outcomes = []
            workers = [threading.Thread(target=lambda: outcomes.append(
                activation.request_activation(name, 0))) for _ in range(12)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=1)
                self.assertFalse(worker.is_alive())
            self.assertEqual(outcomes, [True] * 12)
            release.set()
            self.assertTrue(second.wait(1))
            time.sleep(.1)
            self.assertEqual(len(calls), 2)
        finally:
            release.set()
            channel.close()

    def test_native_close_before_start_and_restart_releases_all_handles(self):
        name = event_name()
        first = activation.InstanceActivation(name)
        first.close()
        first.close()
        self.assertFalse(activation.request_activation(name, 0))
        with self.assertRaises(RuntimeError):
            first.start(lambda: None)
        second = activation.InstanceActivation(name)
        try:
            called = threading.Event()
            second.start(called.set)
            self.assertTrue(activation.request_activation(name, 0))
            self.assertTrue(called.wait(1))
        finally:
            second.close()
        self.assertFalse(activation.request_activation(name, 0))

    def test_native_close_is_bounded_even_if_callback_has_not_returned(self):
        name = event_name()
        channel = activation.InstanceActivation(name)
        entered, release = threading.Event(), threading.Event()
        calls = []
        def callback():
            calls.append(True)
            entered.set()
            release.wait(3)
        try:
            channel.start(callback)
            self.assertTrue(activation.request_activation(name, 0))
            self.assertTrue(entered.wait(1))
            begin = time.monotonic()
            with mock.patch.object(activation, "_JOIN_TIMEOUT", .05):
                channel.close()
            self.assertLess(time.monotonic() - begin, .5)
            # The worker retains ownership until its callback returns.
            self.assertIsNotNone(channel._handle)
            release.set()
            channel._thread.join(timeout=1)
            self.assertFalse(channel._thread.is_alive())
            self.assertIsNone(channel._handle)
            self.assertEqual(calls, [True])
            self.assertFalse(activation.request_activation(name, 0))
        finally:
            release.set()
            channel.close()

    def test_native_idle_close_wakes_wait_without_invoking_callback(self):
        name = event_name()
        channel = activation.InstanceActivation(name)
        callback = mock.Mock()
        channel.start(callback)
        begin = time.monotonic()
        channel.close()
        self.assertLess(time.monotonic() - begin, .5)
        self.assertFalse(channel._thread.is_alive())
        callback.assert_not_called()
        self.assertFalse(activation.request_activation(name, 0))

    def test_native_callback_error_is_contained_and_next_request_still_works(self):
        name = event_name()
        channel = activation.InstanceActivation(name)
        first, second = threading.Event(), threading.Event()
        calls = []
        def callback():
            calls.append(True)
            if len(calls) == 1:
                first.set()
                raise RuntimeError("PRIVATE callback content")
            second.set()
        try:
            with self.assertLogs(activation.log, "WARNING") as captured:
                channel.start(callback)
                channel.start(lambda: self.fail("Must not replace the callback"))
                self.assertTrue(activation.request_activation(name, 0))
                self.assertTrue(first.wait(1))
                self.assertTrue(activation.request_activation(name, 0))
                self.assertTrue(second.wait(1))
            self.assertEqual(len(calls), 2)
            self.assertNotIn("PRIVATE", "\n".join(captured.output))
        finally:
            channel.close()
        self.assertFalse(activation.request_activation(name, 0))

    def test_native_other_namespace_cannot_activate_owner(self):
        name = event_name()
        channel = activation.InstanceActivation(name)
        called = threading.Event()
        try:
            channel.start(called.set)
            self.assertFalse(activation.request_activation(event_name(), 0))
            self.assertFalse(called.wait(.05))
            self.assertTrue(activation.request_activation(name, 0))
            self.assertTrue(called.wait(1))
        finally:
            channel.close()

    def test_native_missing_owner_timeout_is_bounded(self):
        begin = time.monotonic()
        self.assertFalse(activation.request_activation(event_name(), timeout=.075))
        self.assertGreaterEqual(time.monotonic() - begin, .06)
        self.assertLess(time.monotonic() - begin, .5)


class ActivationInteropTest(unittest.TestCase):
    def test_names_and_timeout_reject_global_or_unbounded_requests(self):
        for invalid in ("Global\\TGProxy", "TgWsProxy", "Local\\A\\B", "Local\\", "Local\\A\n"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                activation.InstanceActivation(invalid)
        for value in (float("nan"), float("inf"), -1, 31):
            with self.subTest(timeout=value), self.assertRaises(ValueError):
                activation.request_activation(event_name(), value)

    def test_second_instance_only_opens_event_and_closes_handle_on_set_failure(self):
        api = mock.Mock()
        large_handle = 0x123456789ABCDEF
        api.OpenEventW.return_value = large_handle
        api.SetEvent.return_value = False
        with mock.patch.object(activation, "_kernel32", return_value=api):
            self.assertFalse(activation.request_activation(event_name(), 0))
        api.CreateEventW.assert_not_called()
        api.OpenEventW.assert_called_once_with(activation._EVENT_MODIFY_STATE, False, mock.ANY)
        api.SetEvent.assert_called_once_with(large_handle)
        api.CloseHandle.assert_called_once_with(large_handle)

    def test_close_never_closes_handle_while_wait_is_active(self):
        waiting, wake = threading.Event(), threading.Event()
        api = mock.Mock()
        api.CreateEventW.return_value = 0x123456789ABCDEF
        def wait(handle, timeout):
            waiting.set()
            wake.wait(1)
            waiting.clear()
            return activation._WAIT_OBJECT_0
        def close(handle):
            self.assertFalse(waiting.is_set())
            return True
        api.WaitForSingleObject.side_effect = wait
        api.SetEvent.side_effect = lambda handle: wake.set() or True
        api.CloseHandle.side_effect = close
        with mock.patch.object(activation, "_kernel32", return_value=api):
            channel = activation.InstanceActivation(event_name())
            callback = mock.Mock()
            channel.start(callback)
            self.assertTrue(waiting.wait(1))
            channel.close()
        callback.assert_not_called()
        api.CloseHandle.assert_called_once_with(0x123456789ABCDEF)

    @unittest.skipUnless(sys.platform == "win32", "WinDLL metadata")
    def test_winapi_uses_last_error_and_pointer_sized_handles(self):
        real_windll = ctypes.WinDLL
        with mock.patch.object(activation.ctypes, "WinDLL", wraps=real_windll) as loader:
            api = activation._kernel32()
        loader.assert_called_once_with("kernel32", use_last_error=True)
        self.assertEqual(ctypes.sizeof(api.CreateEventW.restype), ctypes.sizeof(ctypes.c_void_p))
        self.assertEqual(ctypes.sizeof(api.OpenEventW.restype), ctypes.sizeof(ctypes.c_void_p))
        self.assertEqual(ctypes.sizeof(api.WaitForSingleObject.argtypes[0]), ctypes.sizeof(ctypes.c_void_p))
