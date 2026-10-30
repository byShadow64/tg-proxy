import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ui import external_links as links
from ui.background_task import BackgroundTask


class Owner:
    def __init__(self):
        self.pending = {}
        self.sequence = 0
        self.copied = None
        self.bindings = []
    def bind(self, event, callback, **kwargs):
        self.bindings.append(callback)
    def after(self, delay, callback):
        self.sequence += 1
        self.pending[self.sequence] = callback
        return self.sequence
    def after_cancel(self, key):
        self.pending.pop(key, None)
    def clipboard_clear(self):
        self.copied = ''
    def clipboard_append(self, text):
        self.copied += text
    def pump(self):
        deadline = time.monotonic() + 1
        while self.pending and time.monotonic() < deadline:
            pending, self.pending = self.pending, {}
            for callback in pending.values():
                callback()
            time.sleep(.002)


class ExternalLinksTest(unittest.TestCase):
    def test_failed_worker_start_restores_state_and_allows_retry(self):
        owner = Owner()
        task = BackgroundTask(owner)
        completed = []
        with patch('ui.background_task.threading.Thread.start', side_effect=RuntimeError('SYNTHETIC-PRIVATE')):
            with self.assertLogs('tg-ws-tray') as logs:
                self.assertFalse(task.start(lambda: True, completed.append, lambda: completed.append('finish')))
        self.assertFalse(task.running)
        self.assertEqual(completed, ['finish'])
        self.assertNotIn('SYNTHETIC', str(logs.output))
        task.start(lambda: 'ok', completed.append, lambda: completed.append('done'))
        owner.pump()
        self.assertEqual(completed, ['finish', 'ok', 'done'])

    def test_browser_false_and_exception_prompt_manual_copy_on_ui_thread(self):
        for error in (False, OSError('SYNTHETIC-PRIVATE-ENV')):
            owner = Owner()
            main = threading.get_ident()
            worker = []
            def launch(url):
                worker.append(threading.get_ident())
                if isinstance(error, Exception):
                    raise error
                return error
            with patch.object(links.webbrowser, 'open', launch), patch.object(links.messagebox, 'askyesno', return_value=True) as prompt:
                links.open_release_page('https://example.invalid/releases', parent=owner)
                owner.pump()
            self.assertNotEqual(worker[0], main)
            self.assertEqual(owner.copied, 'https://example.invalid/releases')
            self.assertNotIn('SYNTHETIC', str(prompt.call_args))

    def test_singleflight_invalid_url_safe_fallback_and_no_automatic_copy(self):
        owner = Owner()
        release = threading.Event()
        def launch(url):
            release.wait(.5)
            return False
        with patch.object(links.webbrowser, 'open', side_effect=launch) as browser, patch.object(links.messagebox, 'askyesno', return_value=False):
            links.open_release_page('file:///C:/private', parent=owner)
            links.open_release_page('https://example.org', parent=owner)
            release.set()
            owner.pump()
        browser.assert_called_once_with(links.RELEASES_PAGE_URL)
        self.assertIsNone(owner.copied)

    def test_close_cancels_probe_and_ignores_late_result(self):
        owner = Owner()
        task = BackgroundTask(owner)
        exited = threading.Event()
        completed = []
        def work(cancel):
            cancel.wait(.5)
            exited.set()
            return True
        task.start(work, completed.append, lambda: completed.append('finish'), cancellable=True)
        task._on_destroy(SimpleNamespace(widget=owner))
        self.assertTrue(exited.wait(.5))
        owner.pump()
        self.assertFalse(completed)
        self.assertTrue(task.closed)
