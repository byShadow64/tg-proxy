from __future__ import annotations

import logging
import queue
import threading

log = logging.getLogger("tg-ws-tray")


class BackgroundTask:
    def __init__(self, owner):
        self.owner = owner
        self.running = False
        self.closed = False
        self.pending = None
        self.cancel_event = threading.Event()
        owner.bind("<Destroy>", self._on_destroy, add="+")

    def _on_destroy(self, event):
        if event.widget is self.owner:
            self.closed = True
            self.cancel_event.set()
            if self.pending is not None:
                self.owner.after_cancel(self.pending)
                self.pending = None

    def cancel(self):
        self.cancel_event.set()

    def start(self, work, complete, finish, *, cancellable=False):
        if self.running or self.closed:
            return
        self.running = True
        self.cancel_event = threading.Event()
        cancel = self.cancel_event
        results = queue.Queue(maxsize=1)

        def run():
            try:
                results.put((True, work(cancel) if cancellable else work()))
            except Exception:
                log.error("Background task failed")
                results.put((False, None))

        def poll():
            self.pending = None
            if self.closed:
                return
            try:
                success, result = results.get_nowait()
            except queue.Empty:
                self.pending = self.owner.after(50, poll)
                return
            self.running = False
            try:
                if success and not cancel.is_set():
                    complete(result)
            finally:
                if not self.closed:
                    finish()

        try:
            threading.Thread(target=run, daemon=True, name="ui-background-task").start()
        except Exception:
            self.running = False
            cancel.set()
            log.error("Background task could not start")
            if not self.closed:
                finish()
            return False
        self.pending = self.owner.after(50, poll)
        return True
