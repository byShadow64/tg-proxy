"""Atomic update records tolerate only bounded Windows sharing conflicts."""
import errno
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from utils import update_installer as installer


def sharing_error(code):
    error = PermissionError(errno.EACCES, 'synthetic record sharing conflict')
    error.winerror = code
    return error


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class UpdateJsonRetryTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'state.json'
        self.temporary = self.path.with_name('state.json.tmp')
        self.old = b'{"stage":"old"}'
        self.new = {'stage': 'complete', 'description': 'synthetic record'}
        self.path.write_bytes(self.old)

    def test_each_windows_sharing_error_retries_then_commits_valid_json(self):
        replace = installer.os.replace
        for code in (5, 32, 33):
            with self.subTest(winerror=code):
                self.path.write_bytes(self.old)
                clock = Clock()
                failures = [sharing_error(code), sharing_error(code)]

                def attempt(source, destination):
                    if failures:
                        raise failures.pop(0)
                    return replace(source, destination)

                with mock.patch.object(installer.sys, 'platform', 'win32'), \
                        mock.patch.object(installer, 'time', clock), \
                        mock.patch.object(installer.os, 'replace', side_effect=attempt) as replaced:
                    installer.write_json(self.path, self.new)
                self.assertEqual(replaced.call_count, 3)
                self.assertEqual(clock.sleeps, [.02, .02])
                self.assertEqual(json.loads(self.path.read_text()), self.new)
                self.assertFalse(self.temporary.exists())

    def test_deadline_preserves_old_record_and_single_prepared_temporary(self):
        clock = Clock()
        error = sharing_error(32)
        original_open = Path.open
        writes = []

        def opened(path, *args, **kwargs):
            mode = args[0] if args else kwargs.get('mode', 'r')
            if path == self.temporary and 'w' in mode:
                writes.append(path)
            return original_open(path, *args, **kwargs)

        with mock.patch.object(installer.sys, 'platform', 'win32'), \
                mock.patch.object(installer, 'time', clock), \
                mock.patch.object(Path, 'open', opened), \
                mock.patch.object(installer.os, 'replace', side_effect=error) as replaced:
            with self.assertRaises(PermissionError) as caught:
                installer.write_json(self.path, self.new)
        self.assertIs(caught.exception, error)
        self.assertGreater(replaced.call_count, 1)
        self.assertGreaterEqual(clock.now, 2)
        self.assertLessEqual(clock.now, 2.02)
        self.assertTrue(all(0 < delay <= .02 for delay in clock.sleeps))
        self.assertEqual(writes, [self.temporary])
        self.assertEqual(self.path.read_bytes(), self.old)
        self.assertEqual(json.loads(self.temporary.read_text()), self.new)

    def test_non_windows_sharing_error_is_immediate(self):
        clock = Clock()
        error = sharing_error(32)
        with mock.patch.object(installer.sys, 'platform', 'linux'), \
                mock.patch.object(installer, 'time', clock), \
                mock.patch.object(installer.os, 'replace', side_effect=error) as replaced:
            with self.assertRaises(PermissionError) as caught:
                installer.write_json(self.path, self.new)
        self.assertIs(caught.exception, error)
        replaced.assert_called_once()
        self.assertFalse(clock.sleeps)
        self.assertEqual(self.path.read_bytes(), self.old)

    def test_other_windows_and_native_io_errors_are_immediate(self):
        errors = [sharing_error(112), sharing_error(2), OSError(errno.EIO, 'synthetic permanent IO error')]
        for error in errors:
            with self.subTest(winerror=getattr(error, 'winerror', None)):
                clock = Clock()
                with mock.patch.object(installer.sys, 'platform', 'win32'), \
                        mock.patch.object(installer, 'time', clock), \
                        mock.patch.object(installer.os, 'replace', side_effect=error) as replaced:
                    with self.assertRaises(OSError) as caught:
                        installer.write_json(self.path, self.new)
                self.assertIs(caught.exception, error)
                replaced.assert_called_once()
                self.assertFalse(clock.sleeps)
                self.assertEqual(self.path.read_bytes(), self.old)

    def test_retry_rechecks_canonical_and_temporary_path_guards(self):
        original = installer._ordinary
        for rejected in (self.path, self.temporary):
            with self.subTest(path=rejected.name):
                clock = Clock()
                attempted = []

                def attempt(source, destination):
                    attempted.append((source, destination))
                    raise sharing_error(32)

                def guarded(path, *, required=False):
                    if attempted and path == rejected:
                        raise ValueError('synthetic unsafe path after first attempt')
                    return original(path, required=required)

                with mock.patch.object(installer.sys, 'platform', 'win32'), \
                        mock.patch.object(installer, 'time', clock), \
                        mock.patch.object(installer, '_ordinary', side_effect=guarded), \
                        mock.patch.object(installer.os, 'replace', side_effect=attempt) as replaced:
                    with self.assertRaisesRegex(ValueError, 'unsafe path'):
                        installer.write_json(self.path, self.new)
                replaced.assert_called_once()
                self.assertEqual(self.path.read_bytes(), self.old)
                self.assertEqual(json.loads(self.temporary.read_text()), self.new)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows record sharing semantics')
    def test_real_held_reader_released_after_first_failure_allows_atomic_commit(self):
        replace = installer.os.replace
        first_failure = threading.Event()
        released = threading.Event()
        failures = []
        reader = self.path.open('r', encoding='utf-8')
        self.addCleanup(reader.close)

        def release_reader():
            if first_failure.wait(1):
                time.sleep(.1)
            reader.close()
            released.set()

        def attempt(source, destination):
            try:
                return replace(source, destination)
            except OSError as error:
                failures.append(getattr(error, 'winerror', None))
                first_failure.set()
                raise

        worker = threading.Thread(target=release_reader, daemon=True)
        worker.start()
        try:
            with mock.patch.object(installer.os, 'replace', side_effect=attempt):
                installer.write_json(self.path, self.new)
        finally:
            reader.close()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(first_failure.is_set())
        self.assertTrue(released.is_set())
        self.assertTrue(failures)
        self.assertTrue(all(code in (5, 32, 33) for code in failures))
        self.assertEqual(json.loads(self.path.read_text()), self.new)
        self.assertFalse(self.temporary.exists())


if __name__ == '__main__':
    unittest.main()
