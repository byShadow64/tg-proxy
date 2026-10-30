"""Non-blocking connection checks in the dashboard, with explicit cancellation."""
from __future__ import annotations

import logging
import queue
import threading
from tkinter import TclError

from ui.i18n import get_language, t
from ui.icons import icon_image
from utils import connection_diagnostics as diagnostics

log = logging.getLogger("tg-diagnostics")

_KINDS = frozenset({"local", "direct", "fronted", "helper", "cf", "worker", "h2", "tcp"})
_ERRORS = frozenset({
    "proxy_stopped", "invalid_config", "dns", "timeout", "refused", "unreachable", "tls",
    "helper_rejected", "http_forbidden", "http_rate_limited", "http_server_error",
    "http_redirect", "ws_upgrade", "http_error", "connection", "not_configured", "disabled",
    "legacy_unconfirmed", "h2_unconfirmed", "tcp_unconfirmed", "insecure_skipped",
    "not_applicable", "cancelled", "deadline",
})
_UNCONFIRMED = frozenset({"legacy_unconfirmed", "h2_unconfirmed", "tcp_unconfirmed"})
_TRANSPORT_KINDS = frozenset({"direct", "fronted", "helper", "cf", "worker"})


def _result_counts(results):
    """Count outcomes, without treating an untested protocol as an error."""
    counts = dict.fromkeys(("ok", "error", "unconfirmed", "skipped", "cancelled"), 0)
    for item in results:
        status = item.status
        if status == "incomplete" or status == "skipped" and item.error_code in _UNCONFIRMED:
            category = "unconfirmed"
        else:
            category = status if status in counts else "unconfirmed"
        counts[category] += 1
    return counts


def _outcome_key(results, report_status):
    """An alternative transport succeeding does not erase other failures."""
    if any(item.kind == "local" and item.status == "error" for item in results):
        return "local_unavailable"
    counts = _result_counts(results)
    if any(item.kind in _TRANSPORT_KINDS and item.status == "ok" for item in results):
        if counts["error"]:
            return "available_with_errors"
        if report_status == "partial" or counts["unconfirmed"]:
            return "partial_available"
        return "available"
    return "issues" if counts["error"] else "partial"


class ConnectionDiagnostics:
    def __init__(self, ctk, parent, theme, *, get_snapshot, running,
                 on_restart, on_routes, on_telegram):
        self.owner = parent.winfo_toplevel()
        self.parent = parent
        self.theme = theme
        self.get_snapshot, self.running = get_snapshot, running
        self.on_restart, self.on_routes, self.on_telegram = on_restart, on_routes, on_telegram
        self.closed = self.stale = self._cancelling = self._failed = False
        self._run_id = 0
        self._pending = self._worker = self._cancel = None
        self._identity = None
        self._queue = queue.Queue()
        self.results = []
        self._rendered_rows = ()
        self.report = None
        self.completed = self.total = 0
        self._copied = False
        self._language = get_language()
        self._appearance = ctk.get_appearance_mode().lower()
        self.frame = ctk.CTkFrame(parent, fg_color=theme.surface, corner_radius=15,
                                border_width=1, border_color=theme.field_border)
        self.frame.grid_columnconfigure(0, weight=1)
        self.title = ctk.CTkLabel(self.frame, text="", width=1, anchor="w",
                                font=(theme.ui_font_family, 13, "bold"))
        self.title.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 0))
        self.hint = ctk.CTkLabel(self.frame, text="", width=1, anchor="w", justify="left", wraplength=520,
                               font=(theme.ui_font_family, 11), text_color=theme.text_secondary)
        self.hint.grid(row=1, column=0, sticky="ew", padx=20, pady=(5, 12))
        controls = ctk.CTkFrame(self.frame, fg_color="transparent")
        controls.grid(row=2, column=0, sticky="ew", padx=20)
        controls.grid_columnconfigure(1, weight=1)
        self.check_button = ctk.CTkButton(
            controls, text="", height=36, width=180, corner_radius=9,
            font=(theme.ui_font_family, 11, "bold"), fg_color=theme.accent_soft,
            hover_color=theme.field_border, text_color=theme.accent,
            image=icon_image("connection", theme, 16, color="accent"), command=self.start,
        )
        self.check_button.grid(row=0, column=0, sticky="w")
        self.cancel_button = ctk.CTkButton(
            controls, text="", height=34, width=100, corner_radius=9,
            font=(theme.ui_font_family, 11), fg_color="transparent",
            hover_color=theme.surface_alt, text_color=theme.text_secondary, command=self.cancel,
        )
        self.cancel_button.grid(row=0, column=2, sticky="e", padx=(8, 0))
        self.summary = ctk.CTkLabel(self.frame, text="", width=1, anchor="w", justify="left", wraplength=520,
                                  font=(theme.ui_font_family, 11), text_color=theme.text_secondary)
        self.summary.grid(row=3, column=0, sticky="ew", padx=20, pady=(10, 8))
        self.progress = ctk.CTkProgressBar(self.frame, height=4, corner_radius=2)
        self.progress.grid(row=4, column=0, sticky="ew", padx=20, pady=(0, 10))
        self.progress.set(0)
        self.result_text = ctk.CTkTextbox(
            self.frame, height=210, corner_radius=9, fg_color=theme.code_bg,
            font=(theme.ui_font_family, 11), wrap="word", state="disabled",
            border_width=0, activate_scrollbars=True,
        )
        self.result_text.grid(row=5, column=0, sticky="ew", padx=20, pady=(0, 10))
        self._wheel_tag = f"DiagnosticsWheel:{self.result_text}"
        self._wheel_bindings = {}
        for sequence in ("<MouseWheel>", "<Shift-MouseWheel>", "<Button-4>", "<Button-5>"):
            self._wheel_bindings[sequence] = self.owner.bind_class(
                self._wheel_tag, sequence, lambda event: "break")
        self._wheel_widgets = []
        pending = [self.result_text]
        while pending:
            widget = pending.pop()
            tags = list(widget.bindtags())
            # Keep native Text/scrollbar scrolling, then stop before CTk's
            # global bind_all handler also scrolls the surrounding Overview.
            tags.insert(tags.index("all") if "all" in tags else len(tags), self._wheel_tag)
            widget.bindtags(tuple(tags))
            self._wheel_widgets.append(widget)
            pending.extend(widget.winfo_children())
        self.coverage = ctk.CTkLabel(self.frame, text="", width=1, anchor="w", justify="left", wraplength=520,
                                   font=(theme.ui_font_family, 10), text_color=theme.text_muted)
        self.coverage.grid(row=6, column=0, sticky="ew", padx=20, pady=(0, 8))
        self.advice = ctk.CTkLabel(self.frame, text="", width=1, anchor="w", justify="left", wraplength=520,
                                 font=(theme.ui_font_family, 11), text_color=theme.text_secondary)
        self.advice.grid(row=7, column=0, sticky="ew", padx=20, pady=(0, 8))
        actions = ctk.CTkFrame(self.frame, fg_color="transparent")
        actions.grid(row=8, column=0, sticky="ew", padx=20, pady=(0, 16))
        actions.grid_columnconfigure(1, weight=1)
        self.action_button = ctk.CTkButton(
            actions, text="", height=32, width=160, corner_radius=8,
            font=(theme.ui_font_family, 11), fg_color="transparent",
            hover_color=theme.surface_alt, text_color=theme.accent, command=self.act,
        )
        self.action_button.grid(row=0, column=0, sticky="w")
        self.copy_button = ctk.CTkButton(
            actions, text="", height=32, width=175, corner_radius=8,
            font=(theme.ui_font_family, 11), fg_color="transparent",
            hover_color=theme.surface_alt, text_color=theme.text_secondary,
            image=icon_image("copy", theme, 14), command=self.copy_report,
        )
        self.copy_button.grid(row=0, column=2, sticky="e")
        self.frame.bind("<Configure>", self._fit, add="+")
        self.owner.bind("<Destroy>", self._destroyed, add="+")
        self._render()

    @property
    def checking(self):
        return self._worker is not None

    def _fit(self, event):
        canvas = self.parent._parent_canvas
        available = min(event.width, canvas.winfo_width())
        width = max(220, min(520, int(available / self.frame._get_widget_scaling()) - 40))
        for widget in (self.hint, self.summary, self.coverage, self.advice):
            widget.configure(wraplength=width)

    def _destroyed(self, event):
        if event.widget is self.owner:
            self.close()

    def start(self):
        if self.closed or self.checking:
            return
        try:
            snapshot = self.get_snapshot()
        except Exception as exc:
            log.warning("Could not prepare connection check (%s)", type(exc).__name__)
            self._failed = True
            self.report = None
            self._render()
            return
        self._run_id += 1
        run_id = self._run_id
        self._identity = snapshot.identity
        self.stale = self._cancelling = self._failed = self._copied = False
        self.results, self.report = [], None
        self.completed = self.total = 0
        cancel = self._cancel = threading.Event()

        def emit(event):
            self._queue.put((run_id, "progress", event))

        def work():
            try:
                report = diagnostics.run_diagnostics(snapshot, cancel, emit)
            except Exception as exc:
                log.warning("Connection check could not finish (%s)", type(exc).__name__)
                self._queue.put((run_id, "failed", None))
            else:
                self._queue.put((run_id, "done", report))

        self._worker = threading.Thread(target=work, daemon=True, name="connection-diagnostics")
        self._render()
        try:
            self._worker.start()
        except RuntimeError:
            self._worker = None
            self._failed = True
            log.warning("Connection check worker could not start")
            self._render()
            return
        self._pending = self.owner.after(50, self._poll)

    def cancel(self):
        if self.closed or not self.checking:
            return
        self._cancelling = True
        self._cancel.set()
        self._render()

    def _poll(self):
        self._pending = None
        if self.closed:
            return
        changed = False
        while True:
            try:
                run_id, kind, value = self._queue.get_nowait()
            except queue.Empty:
                break
            if run_id != self._run_id:
                continue
            if kind == "progress" and not self.stale:
                if value.get("kind") == "progress":
                    self.results.append(value["result"])
                    self.completed, self.total = value["completed"], value["total"]
            elif kind in ("done", "failed"):
                self._worker = None
                self._failed = kind == "failed"
                if not self.stale and kind == "done":
                    self.report = value
                    self.results = list(value.results)
                self._cancelling = False
            changed = True
        self.refresh()
        if changed:
            self._render()
        if self.checking and not self.closed:
            self._pending = self.owner.after(50, self._poll)

    def refresh(self):
        if self.closed:
            return
        appearance = self.result_text._get_appearance_mode()
        changed = self._language != get_language() or self._appearance != appearance
        self._language = get_language()
        self._appearance = appearance
        if self._identity is not None and not self.stale:
            try:
                current = self.get_snapshot().identity
            except Exception:
                current = None
            if current != self._identity:
                self.stale = True
                self.report = None
                if self.checking:
                    self._cancel.set()
                changed = True
        if changed:
            self._render()

    def _render(self):
        if self.closed:
            return
        theme = self.theme
        self.title.configure(text=t("connection_diagnostics.title"))
        self.hint.configure(text=t("connection_diagnostics.hint") + "\n" +
                            t("connection_diagnostics.scope", limit=diagnostics.MAX_CANDIDATES))
        self.check_button.configure(text=t("connection_diagnostics.retry" if self._identity is not None
                                           else "connection_diagnostics.check"),
                                    state="disabled" if self.checking else "normal")
        self.cancel_button.configure(text=t("connection_diagnostics.cancel"),
                                     state="normal" if self.checking and not self._cancelling and not self.stale
                                     else "disabled")
        if self.stale:
            key, color = "stale", theme.warning
        elif self._cancelling:
            key, color = "cancelling", theme.text_secondary
        elif self.checking:
            key, color = "checking", theme.text_secondary
        elif self._failed:
            key, color = "failed", theme.danger
        elif self.report is None:
            key, color = "idle", theme.text_muted
        elif self.report.status == "cancelled":
            key, color = "cancelled", theme.text_secondary
        else:
            key = _outcome_key(self.results, self.report.status)
            color = (theme.success if key == "available" else theme.danger
                     if key == "local_unavailable" else theme.warning)
        summary = t(f"connection_diagnostics.{key}", completed=self.completed, total=self.total)
        if self.results and not self.stale:
            summary += "\n" + t("connection_diagnostics.counts", **_result_counts(self.results))
        self.summary.configure(text=summary, text_color=color)
        self.progress.set(min(1, self.completed / self.total) if self.total else 0)
        if self._identity is None:
            self.progress.grid_remove()
            self.result_text.grid_remove()
        else:
            self.progress.grid()
            self.result_text.grid()
        self._render_results()
        coverage = self.report.coverage if self.report is not None and not self.stale else ()
        if coverage:
            self.coverage.configure(text=" · ".join(
                t("connection_diagnostics.coverage", kind=t(f"connection_diagnostics.kind.{item.kind}"),
                  tested=item.tested, total=item.total)
                for item in coverage if item.kind in _KINDS and item.total
            ))
            self.coverage.grid()
        else:
            self.coverage.grid_remove()
        recommendation = self.report.recommendation if self.report is not None and not self.stale else None
        self.action_button.grid_remove()
        self.advice.grid_remove()
        if recommendation in {"start_proxy", "open_routes", "open_telegram", "retry"} and not self.checking:
            self.advice.configure(text=t(f"connection_diagnostics.advice.{recommendation}"))
            self.advice.grid()
            self.action_button.configure(text=t(f"connection_diagnostics.action.{recommendation}"))
            self.action_button.grid()
        self.copy_button.configure(text=t("connection_diagnostics.copied" if self._copied
                                         else "connection_diagnostics.copy"),
                                   state="normal" if self.report is not None and not self.stale
                                   and not self.checking else "disabled")

    def _render_results(self):
        text = self.result_text
        native = text._textbox
        at_tail = native.yview()[1] >= .999
        top_index = native.index("@0,0")
        # CTk resolves light/dark text colors; tkinter tags need a concrete color.
        for status, color in (("ok", self.theme.success), ("error", self.theme.danger),
                              ("skipped", self.theme.text_muted), ("incomplete", self.theme.warning),
                              ("cancelled", self.theme.text_muted)):
            text.tag_config(status, foreground=text._apply_appearance_mode(color))
        rows = []
        for result in self.results:
            kind = result.kind if result.kind in _KINDS else "direct"
            label = t(f"connection_diagnostics.kind.{kind}")
            if result.dc is not None:
                label += t("connection_diagnostics.dc", dc=result.dc)
                if result.media is not None:
                    label += t("connection_diagnostics.media" if result.media else "connection_diagnostics.messages")
            # Aliases identify custom candidates without disclosing their address.
            if kind in {"cf", "worker"}:
                index = getattr(result, "candidate_index", 0)
                if isinstance(index, int) and 1 <= index <= 3:
                    label += f" #{index}"
            status = result.status if result.status in {"ok", "error", "skipped", "cancelled", "incomplete"} else "incomplete"
            line = label + " — " + t(f"connection_diagnostics.status.{status}")
            if result.setup_ms is not None:
                line += t("connection_diagnostics.milliseconds", milliseconds=round(result.setup_ms))
            if result.error_code:
                code = result.error_code if result.error_code in _ERRORS else "connection"
                line += ": " + t(f"connection_diagnostics.error.{code}")
            rows.append((line + "\n", status))
        rows = tuple(rows)
        if rows == self._rendered_rows:
            return  # Theme/tag changes do not require replacing the text.
        text.configure(state="normal")
        append_only = rows[:len(self._rendered_rows)] == self._rendered_rows
        if append_only:
            added = rows[len(self._rendered_rows):]
        else:
            text.delete("1.0", "end")
            added = rows
        for line, status in added:
            text.insert("end", line, status)
        text.configure(state="disabled")
        self._rendered_rows = rows
        if at_tail:
            native.see("end")
        elif not append_only:
            # Retain the visible logical line when language or a replaced
            # result changes the text. Appending preserves Tk's own viewport.
            native.yview(top_index)

    def act(self):
        self.refresh()
        if self.closed or self.checking or self.stale or self.report is None:
            return
        action = self.report.recommendation
        if action == "start_proxy":
            if not self.running():
                self.on_restart()
        elif action == "open_routes":
            self.on_routes()
        elif action == "open_telegram":
            if self.running():
                self.on_telegram()
        elif action == "retry":
            self.start()

    def copy_report(self):
        self.refresh()
        if self.closed or self.checking or self.stale or self.report is None:
            return
        try:
            text = diagnostics.format_report(self.report)
            self.owner.clipboard_clear()
            self.owner.clipboard_append(text)
        except (TclError, ValueError, TypeError) as exc:
            log.warning("Could not copy connection report (%s)", type(exc).__name__)
            return
        self._copied = True
        self._render()

    def close(self):
        if self.closed:
            return
        self.closed = True
        for widget in self._wheel_widgets:
            try:
                widget.bindtags(tuple(tag for tag in widget.bindtags() if tag != self._wheel_tag))
            except TclError:
                pass
        for sequence, command in self._wheel_bindings.items():
            try:
                self.owner.unbind_class(self._wheel_tag, sequence)
                self.owner._root().deletecommand(command)
            except TclError:
                pass
        self._wheel_widgets.clear()
        self._wheel_bindings.clear()
        if self._cancel is not None:
            self._cancel.set()
        if self._pending is not None:
            try:
                self.owner.after_cancel(self._pending)
            except TclError:
                pass
            self._pending = None
