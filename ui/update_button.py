"""Manual release checks in the sidebar, independent of startup preferences."""
from __future__ import annotations

import logging
import sys
from tkinter import TclError

from proxy import __version__
from proxy.project import REPOSITORY
from proxy.utils import human_bytes
from ui.background_task import BackgroundTask
from ui.i18n import get_language, t
from ui.icons import icon_image
from ui.external_links import open_release_page
from utils import update_check, update_progress
from utils.windows_update import asset_name


log = logging.getLogger("tg-ws-tray")


class SidebarUpdates:
    def __init__(self, ctk, parent, theme, *, on_update=None):
        self.theme, self.on_update = theme, on_update
        self.frame = ctk.CTkFrame(parent, fg_color="transparent", corner_radius=0)
        self.task = BackgroundTask(parent.winfo_toplevel())
        self._checking = False
        self._language = get_language()
        self._snapshot = update_check.get_status()
        self._seen_state = self._snapshot
        self._progress = update_progress.get_progress()
        self._animating = False
        self._closed = False
        self.button = ctk.CTkButton(
            self.frame, text="", height=48, width=142, corner_radius=10,
            font=(theme.ui_font_family, 11, "bold"),
            fg_color=theme.accent_soft, hover_color=theme.field_border,
            text_color=theme.accent, text_color_disabled=theme.text_muted,
            image=icon_image("restart", theme, 16, color="accent"),
            command=self.check,
        )
        self.button.pack(fill="x")
        self.source = ctk.CTkLabel(
            self.frame, text=REPOSITORY, anchor="w", height=16,
            font=(theme.ui_font_family, 9), text_color=theme.text_muted,
        )
        self.source.pack(fill="x", pady=(6, 0))
        self.status = ctk.CTkLabel(
            self.frame, text="", width=1, anchor="w", justify="left", wraplength=142,
            height=1, font=(theme.ui_font_family, 10), text_color=theme.text_secondary,
        )
        self.status.pack(fill="x", pady=(4, 0))
        self.progress_frame = ctk.CTkFrame(self.frame, fg_color="transparent", corner_radius=0)
        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame, width=142, height=5, corner_radius=3,
            fg_color=theme.field_border, progress_color=theme.accent,
            mode="determinate", indeterminate_speed=0.8,
        )
        self.progress_bar.pack(fill="x", pady=(5, 0))
        self.progress_details = ctk.CTkLabel(
            self.progress_frame, text="", width=1, height=1, anchor="w", justify="left", wraplength=142,
            font=(theme.mono_font_family, 9), text_color=theme.text_secondary,
        )
        self.progress_details.pack(fill="x", pady=(6, 0))
        self.progress_bar.bind("<Destroy>", lambda event: self._stop_animation(), add="+")
        self.action = ctk.CTkButton(
            self.frame, text="", height=34, width=142, corner_radius=8,
            fg_color=theme.accent, hover_color=theme.accent_hover,
            text_color=theme.on_accent, text_color_disabled=theme.text_muted,
            font=(theme.ui_font_family, 11, "bold"), command=self.open_update,
        )
        parent.winfo_toplevel().bind("<Destroy>", self._on_destroy, add="+")
        self._render()

    def check(self):
        if self.task.closed or self._closed or self.task.running:
            return
        self._progress = update_progress.get_progress()
        if self._progress["active"]:
            self._render()
            return
        update_progress.clear_finished()
        self._checking = True
        self._render()

        def work():
            try:
                update_check.run_check(__version__)
                return update_check.get_status()
            except Exception as exc:
                # Keep the retry UI usable even on an unexpected worker error.
                log.warning("Manual update check failed (%s)", type(exc).__name__)
                return {"checked": True, "error": True, "has_update": False}

        def complete(result):
            self._snapshot = result
            self._seen_state = update_check.get_status()

        def finish():
            self._checking = False
            self._render()

        self.task.start(work, complete, finish)

    def _render(self):
        if self.task.closed or self._closed:
            return
        self._progress = update_progress.get_progress()
        active = self._progress["active"]
        theme, result = self.theme, self._snapshot
        self.button.configure(
            text=t("dashboard.update_progress_busy" if active else
                   "dashboard.update_checking" if self._checking else "dashboard.check_updates"),
            state="disabled" if self._checking or active else "normal",
        )
        self.action.configure(state="disabled" if self._checking or active else "normal")
        self.action.pack_forget()
        self.progress_frame.pack_forget()
        if active:
            self._render_progress()
            return
        self._stop_animation()
        if self._progress["phase"] == "failed" and not self._checking:
            key, color = "dashboard.update_progress_failed", theme.danger
            if result.get("has_update") and result.get("latest"):
                self._render_action(retry=True)
                self.action.pack(fill="x", pady=(4, 0))
        elif self._checking:
            key, color = "dashboard.update_wait", theme.text_secondary
        elif result.get("error"):
            key, color = (("dashboard.update_no_release", theme.text_secondary)
                          if result.get("http_status") == 404
                          else ("dashboard.update_error", theme.danger))
        elif not result.get("checked"):
            key, color = "dashboard.update_hint", theme.text_muted
        elif result.get("github_result") == "no_public_release" and not result.get("latest"):
            key, color = "dashboard.update_no_release", theme.text_secondary
        elif result.get("has_update") and result.get("latest"):
            key, color = "dashboard.update_available", theme.accent
            self._render_action()
            self.action.pack(fill="x", pady=(4, 0))
        elif result.get("ahead_of_release"):
            key, color = "dashboard.update_ahead", theme.text_secondary
        else:
            key, color = "dashboard.update_current", theme.success
        self.status.configure(text=t(key, version=result.get("latest", "")), text_color=color)

    def _render_action(self, *, retry=False):
        # Match the Windows update flow: a source checkout or a release without
        # a verified compatible EXE can only show the release page.
        name = asset_name()
        installable = (self.on_update is not None and getattr(sys, "frozen", False)
                       and name is not None and update_check.find_asset(name) is not None)
        if installable:
            key = "dashboard.update_progress_retry" if retry else "dashboard.open_update"
        else:
            key = "dashboard.update_release_page"
        self.action.configure(
            text=t(key), image=icon_image("download" if installable else "globe",
                                        self.theme, 16, color="on_accent"),
        )

    def _render_progress(self):
        progress = self._progress
        phase = progress["phase"]
        if phase not in {"preparing", "downloading", "verifying", "starting_installer", "restarting"}:
            phase = "preparing"
        self.status.configure(text=t(f"dashboard.update_progress_{phase}"), text_color=self.theme.accent)
        self.progress_frame.pack(fill="x", pady=(3, 0))
        downloaded, total = progress["downloaded"], progress["total"]
        known = total is not None and total > 0
        if known:
            percent = min(100, max(0, int(downloaded * 100 / total)))
            text = t("dashboard.update_progress_known", percent=percent,
                     downloaded=human_bytes(downloaded), total=human_bytes(total))
        else:
            text = t("dashboard.update_progress_unknown", downloaded=human_bytes(downloaded))
        self.progress_details.configure(text=text)
        if known and phase in {"downloading", "verifying"}:
            self._stop_animation()
            self.progress_bar.configure(mode="determinate")
            self.progress_bar.set(min(1.0, max(0.0, downloaded / total)))
        else:
            self.progress_bar.configure(mode="indeterminate")
            if not self._animating:
                self._animating = True
                self.progress_bar.start()

    def _stop_animation(self):
        if self._animating:
            try:
                self.progress_bar.stop()
            except TclError:
                pass
            self._animating = False

    def _on_destroy(self, event):
        if event.widget is self.task.owner:
            self._closed = True
            self._stop_animation()

    def refresh(self):
        if self.task.closed or self._closed:
            return
        language_changed = self._language != get_language()
        self._language = get_language()
        current = update_check.get_status()
        progress_changed = self._progress != update_progress.get_progress()
        if not self._checking and current != self._seen_state:
            self._snapshot = current
            self._seen_state = current
            self._render()
        elif language_changed or progress_changed:
            self._render()

    def open_update(self):
        if self._checking or self.task.closed or self._closed or not self._snapshot.get("has_update"):
            return
        self._progress = update_progress.get_progress()
        if self._progress["active"]:
            self._render()
            return
        update_progress.clear_finished()
        if self.on_update is not None:
            self.on_update()
        else:
            open_release_page(update_check.RELEASES_PAGE_URL, parent=self.task.owner)
