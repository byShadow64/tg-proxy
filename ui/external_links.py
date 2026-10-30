"""Open release links without blocking Tk, with an explicit manual fallback."""
from __future__ import annotations

import webbrowser
from tkinter import messagebox, TclError

from ui.background_task import BackgroundTask
from ui.i18n import t
from utils.update_check import RELEASES_PAGE_URL
from utils.update_manifest import validate_https_url


def open_release_page(url, *, parent):
    try:
        validate_https_url(url)
    except (ValueError, TypeError):
        url = RELEASES_PAGE_URL

    def work():
        try:
            return bool(webbrowser.open(url))
        except Exception:
            return False  # No exception, browser environment or URL in logs.

    def fallback(owner):
        if messagebox.askyesno(t('external_links.title'),
                              t('external_links.copy_prompt', url=url), parent=owner):
            try:
                owner.clipboard_clear()
                owner.clipboard_append(url)
            except TclError:
                messagebox.showerror(t('external_links.title'),
                                     t('external_links.copy_failed', url=url), parent=owner)

    if parent is None:
        # The tray update flow already runs on a worker. A failed browser
        # launch must dispatch its fallback to the app's existing Tk thread.
        if not work():
            import customtkinter as ctk
            from utils import tray_common
            if tray_common.ensure_ctk_thread(ctk):
                def show(done):
                    try:
                        fallback(tray_common._ctk_root)
                    finally:
                        done.set()
                tray_common.ctk_run_dialog(show)
        return
    task = getattr(parent, '_release_link_task', None)
    if task is None:
        task = BackgroundTask(parent)
        parent._release_link_task = task
    if task.running or task.closed:
        return

    def complete(opened):
        if opened:
            return
        fallback(parent)

    task.start(work, complete, lambda: None)
