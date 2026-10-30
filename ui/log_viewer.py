from __future__ import annotations

import logging
import time
from collections import deque
from tkinter import Misc, TclError

from ui.i18n import get_language, t


def level_bucket(levelno):
    """Group custom/critical levels without interpreting message contents."""
    if levelno >= logging.ERROR:
        return "ERROR"
    if levelno >= logging.WARNING:
        return "WARNING"
    if levelno >= logging.INFO:
        return "INFO"
    return "DEBUG"


def filter_entries(entries, level="all", query=""):
    """Search safe history and retain the complete matching multiline event."""
    entries = tuple(entries)
    query = query.strip().casefold()
    matching_records = {
        entry.record_seq or entry.seq for entry in entries
        if query in f"{entry.name} {entry.levelname} {entry.message}".casefold()
    } if query else None
    return tuple(entry for entry in entries
                 if (level == "all" or level_bucket(entry.levelno) == level)
                 and (matching_records is None
                      or (entry.record_seq or entry.seq) in matching_records))


class LogViewer:
    """Read-only log pane. All widget updates happen on the Tk thread."""

    def __init__(self, ctk, parent, theme, source, on_back, *, show_back=True,
                 show_header=True):
        self.source = source
        self.ctk, self.theme = ctk, theme
        self.cursor = None
        self._entries = deque(maxlen=source.max_lines)
        self._visible_entries = ()
        self._level = "all"
        self._filters_changed = False
        self._syncing_filters = False
        self._search_after = None
        self._tag_appearance = None
        self._language = get_language()
        self._translated_widgets = []
        self._status_key = "logs.history"
        self.frame = ctk.CTkFrame(parent, fg_color="transparent", corner_radius=0)
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_rowconfigure(1, weight=1)

        toolbar = ctk.CTkFrame(self.frame, fg_color="transparent")
        if show_header:
            toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        toolbar.grid_columnconfigure(1, weight=1)
        if show_back:
            self._localized(ctk.CTkButton(
                toolbar, width=92, height=36, command=on_back,
                corner_radius=10, fg_color=theme.surface_alt,
                hover_color=theme.field_border, text_color=theme.text_primary,
                font=(theme.ui_font_family, 12),
            ), "logs.overview").grid(row=0, column=0, padx=(0, 14))
        self._localized(ctk.CTkLabel(
            toolbar, anchor="w", height=36,
            font=(theme.ui_font_family, 24, "bold"),
            text_color=theme.text_primary,
        ), "logs.title").grid(row=0, column=1, sticky="ew")

        panel = ctk.CTkFrame(
            self.frame, fg_color=theme.surface, corner_radius=14,
            border_width=1, border_color=theme.field_border,
        )
        panel.grid(row=1, column=0, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(2, weight=1)

        actions = ctk.CTkFrame(panel, fg_color="transparent")
        actions.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 12))
        actions.grid_columnconfigure(0, weight=1)
        self._localized(ctk.CTkLabel(
            actions, anchor="w", font=(theme.ui_font_family, 12, "bold"),
            text_color=theme.text_secondary,
        ), "logs.stream_label").grid(row=0, column=0, sticky="ew")

        live = ctk.CTkFrame(
            toolbar if show_header else actions,
            fg_color=theme.accent_soft, corner_radius=12,
        )
        live.grid(row=0, column=2 if show_header else 1, sticky="e")
        ctk.CTkFrame(
            live, width=6, height=6, corner_radius=3,
            fg_color=theme.success,
        ).grid(row=0, column=0, padx=(12, 7), pady=12)
        self._localized(ctk.CTkLabel(
            live, font=(theme.ui_font_family, 11, "bold"),
            text_color=theme.accent, height=28,
        ), "logs.live").grid(row=0, column=1, padx=(0, 12), pady=1)

        self.end_button = self._localized(ctk.CTkButton(
            actions, width=100, height=36, corner_radius=10,
            font=(theme.ui_font_family, 12),
            fg_color="transparent", hover_color=theme.surface_alt,
            text_color=theme.text_secondary,
            command=lambda: self.text.see("end"),
        ), "logs.scroll_end")
        self.end_button.grid(row=0, column=2, padx=(8, 8))
        self.copy_button = self._localized(ctk.CTkButton(
            actions, width=150, height=36, corner_radius=10,
            font=(theme.ui_font_family, 12, "bold"),
            command=self.copy_all, state="disabled",
            fg_color=theme.surface_alt, hover_color=theme.field_border,
            text_color=theme.text_primary, text_color_disabled=theme.text_muted,
        ), "logs.copy_all")
        self.copy_button.grid(row=0, column=3)

        filters = ctk.CTkFrame(panel, fg_color="transparent")
        filters.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        filters.grid_columnconfigure(2, weight=1)
        self.level_menu = ctk.CTkOptionMenu(
            filters, values=self._level_labels(), width=152, height=36,
            corner_radius=9, font=(theme.ui_font_family, 12),
            fg_color=theme.field_bg, button_color=theme.field_bg,
            button_hover_color=theme.surface_alt, text_color=theme.text_primary,
            dropdown_fg_color=theme.surface, dropdown_text_color=theme.text_primary,
            dropdown_hover_color=theme.accent_soft, command=self._change_level,
        )
        self.level_menu.grid(row=0, column=0, padx=(0, 8))
        self.search_label = self._localized(ctk.CTkLabel(
            filters, font=(theme.ui_font_family, 11),
            text_color=theme.text_secondary,
        ), "logs.search_label")
        self.search_label.grid(row=0, column=1, padx=(0, 8))
        self.search_var = ctk.StringVar(master=self.frame, value="")
        self.search_entry = ctk.CTkEntry(
            filters, textvariable=self.search_var, height=36, width=1,
            corner_radius=9, fg_color=theme.field_bg, border_width=1,
            border_color=theme.field_border, text_color=theme.text_primary,
            placeholder_text=t("logs.search_placeholder"),
            placeholder_text_color=theme.text_muted, font=(theme.ui_font_family, 12),
        )
        self.search_entry.grid(row=0, column=2, sticky="ew")
        self.clear_button = self._localized(ctk.CTkButton(
            filters, width=82, height=36, corner_radius=9, state="disabled",
            fg_color="transparent", hover_color=theme.surface_alt,
            text_color=theme.text_secondary, text_color_disabled=theme.text_muted,
            font=(theme.ui_font_family, 11), command=self.clear_filters,
        ), "logs.clear_filters")
        self.clear_button.grid(row=0, column=3, padx=(8, 0))
        self._search_trace = self.search_var.trace_add("write", self._schedule_search)
        self.search_entry.bind("<Escape>", lambda event: self.clear_filters(), add="+")
        # CTkFrame.bind forwards to its canvas, rather than the owning frame.
        # Bind the actual widget so pending search work is cancelled on close.
        Misc.bind(self.frame, "<Destroy>", self._destroy, add="+")

        viewport = ctk.CTkFrame(panel, fg_color=theme.code_bg, corner_radius=10)
        viewport.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))
        viewport.grid_columnconfigure(0, weight=1)
        viewport.grid_rowconfigure(0, weight=1)
        self.text = ctk.CTkTextbox(
            viewport, wrap="word", corner_radius=10, border_spacing=12,
            font=(theme.ui_font_family, 12), fg_color=theme.code_bg,
            text_color=theme.text_primary, border_width=0,
            scrollbar_button_color=theme.field_border,
            scrollbar_button_hover_color=theme.text_muted,
            spacing1=4, spacing3=5, state="disabled",
        )
        self.text.grid(row=0, column=0, sticky="nsew")
        self.text.bind("<Control-KeyPress>", self._keyboard, add="+")

        self.empty_state = ctk.CTkFrame(viewport, fg_color=theme.code_bg, corner_radius=0)
        self.empty_state.grid(row=0, column=0, padx=24, pady=24)
        ctk.CTkLabel(
            self.empty_state, text=">_", height=36,
            font=(theme.mono_font_family, 24), text_color=theme.text_muted,
        ).grid(row=0, column=0, pady=(0, 10))
        self._empty_label = ctk.CTkLabel(
            self.empty_state, wraplength=340, justify="center",
            font=(theme.ui_font_family, 14), text_color=theme.text_secondary,
            text=t("logs.empty"),
        )
        self._empty_label.grid(row=1, column=0)
        self._empty_hint = ctk.CTkLabel(
            self.empty_state, wraplength=340, justify="center", text="",
            font=(theme.ui_font_family, 11), text_color=theme.text_muted,
        )

        footer = ctk.CTkFrame(self.frame, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        footer.grid_columnconfigure(0, weight=1)
        self.status = ctk.CTkLabel(
            footer, text=t("logs.history", count=f"{source.max_lines:,}".replace(",", " ")),
            font=(theme.ui_font_family, 11), text_color=theme.text_muted,
            anchor="w",
        )
        self.status.grid(row=0, column=0, sticky="ew")
        self._localized(ctk.CTkLabel(
            footer, font=(theme.ui_font_family, 11), text_color=theme.text_muted,
        ), "logs.selection_hint").grid(row=0, column=1, sticky="e", padx=(16, 0))
        self._sync_tags()

    def _localized(self, widget, key):
        self._translated_widgets.append((widget, key))
        widget.configure(text=t(key))
        return widget

    def refresh_language(self):
        language = get_language()
        if language == self._language:
            return
        self._language = language
        for widget, key in self._translated_widgets:
            widget.configure(text=t(key))
        self.level_menu.configure(values=self._level_labels())
        self.level_menu.set(t("logs.filter_all") if self._level == "all" else self._level)
        self.search_entry.configure(placeholder_text=t("logs.search_placeholder"))
        self._update_status()
        self._update_empty()

    def refresh(self):
        self.refresh_language()
        self._sync_tags()
        cursor, entries, reset = self.source.read_entries_since(self.cursor)
        if not entries and not reset and not self._filters_changed:
            return
        if reset:
            self._entries.clear()
        self._entries.extend(entries)
        visible = filter_entries(self._entries, self._level, self.search_var.get())
        force = self._filters_changed
        if force:
            self._status_key = "logs.results" if self._filtered() else "logs.history"
        self._render(visible, force=force)
        self.cursor = cursor
        self._filters_changed = False
        self.clear_button.configure(state="normal" if self._filtered() else "disabled")
        self.copy_button.configure(state="normal" if visible else "disabled")
        self._update_empty()
        self._update_status()

    def _render(self, entries, *, force=False):
        old = self._visible_entries
        if not force and entries == old:
            return
        follow = not force and (not old or self.text.yview()[1] >= 0.995)
        removed = 0
        if old and entries and not force:
            removed = next((index for index, entry in enumerate(old)
                            if entry.seq == entries[0].seq), len(old))
        retained = old[removed:]
        incremental = not force and tuple(entry.seq for entry in retained) == tuple(
            entry.seq for entry in entries[:len(retained)])
        self.text.configure(state="normal")
        try:
            if not incremental:
                self.text.delete("1.0", "end")
                retained = ()
            elif removed:
                self.text.delete("1.0", f"{removed + 1}.0")
            for entry in entries[len(retained):]:
                self._insert_entry(entry)
        finally:
            self.text.configure(state="disabled")
        self._visible_entries = entries
        if follow:
            self.text.see("end")
        elif force:
            self.text.yview_moveto(0)

    def _insert_entry(self, entry):
        start = self.text.index("end-1c")
        if entry.continuation:
            self.text.insert("end", "    ", ("log_meta",))
        else:
            stamp = time.strftime("%H:%M:%S", time.localtime(entry.created))
            self.text.insert("end", stamp + "  ", ("log_meta",))
            self.text.insert("end", f" {entry.levelname} ", (f"level_{level_bucket(entry.levelno)}",))
            name = {"tg-mtproto-proxy": "proxy", "tg-ws-tray": "app"}.get(entry.name, entry.name)
            self.text.insert("end", "  " + name + "  " if name else "  ", ("log_logger",))
        self.text.insert("end", entry.message + "\n", ("log_body",))
        self.text.tag_add(f"row_{level_bucket(entry.levelno)}", start, "end-1c")

    def _sync_tags(self):
        appearance = self.ctk.get_appearance_mode()
        scaling = self.text._get_widget_scaling()
        if self._tag_appearance == (appearance, scaling):
            return
        self._tag_appearance = (appearance, scaling)
        mode = int(appearance == "Dark")

        def color(token):
            return token[mode] if isinstance(token, (tuple, list)) else token

        mono = self.text._apply_font_scaling((self.theme.mono_font_family, 10))
        bold = self.text._apply_font_scaling((self.theme.mono_font_family, 10, "bold"))
        # CTk forbids unscaled tag fonts; compute them using the same widget's
        # scaling and update them together with appearance changes.
        self.text._textbox.tag_configure("log_meta", foreground=color(self.theme.text_muted), font=mono)
        self.text._textbox.tag_configure("log_logger", foreground=color(self.theme.text_secondary), font=mono)
        self.text.tag_config("log_body", foreground=color(self.theme.text_primary))
        colors = {
            "INFO": (self.theme.accent, self.theme.accent_soft),
            "WARNING": (self.theme.warning, self.theme.warning_bg),
            "ERROR": (self.theme.danger, self.theme.surface_alt),
            "DEBUG": (self.theme.text_muted, self.theme.field_bg),
        }
        for level, (foreground, background) in colors.items():
            self.text._textbox.tag_configure(
                f"level_{level}", foreground=color(foreground), background=color(background),
                font=bold, borderwidth=2, relief="flat",
            )
            self.text.tag_config(f"row_{level}", foreground=color(
                self.theme.text_muted if level == "DEBUG" else self.theme.text_primary))
        for tag in ("log_meta", "log_logger", *(f"level_{level}" for level in colors)):
            self.text.tag_raise(tag)
        self.text.tag_raise("sel")

    def _level_labels(self):
        return [t("logs.filter_all"), "INFO", "WARNING", "ERROR", "DEBUG"]

    def _filtered(self):
        return self._level != "all" or bool(self.search_var.get().strip())

    def _change_level(self, label):
        self.set_filter(level=label if label in self._level_labels()[1:] else "all")

    def _schedule_search(self, *_):
        if self._syncing_filters:
            return
        if self._search_after is not None:
            self.frame.after_cancel(self._search_after)
        self._search_after = self.frame.after(120, self._search_changed)

    def _search_changed(self):
        self._search_after = None
        self._filters_changed = True
        self.refresh()

    def set_filter(self, *, level=None, query=None):
        if self._search_after is not None:
            self.frame.after_cancel(self._search_after)
            self._search_after = None
        self._syncing_filters = True
        try:
            if level is not None:
                self._level = level if level in ("INFO", "WARNING", "ERROR", "DEBUG") else "all"
                self.level_menu.set(t("logs.filter_all") if self._level == "all" else self._level)
            if query is not None:
                self.search_var.set(query)
        finally:
            self._syncing_filters = False
        self._filters_changed = True
        self.refresh()

    def clear_filters(self):
        self.set_filter(level="all", query="")

    def _destroy(self, event):
        if event.widget is not self.frame:
            return
        if self._search_after is not None:
            self.frame.after_cancel(self._search_after)
            self._search_after = None
        if self._search_trace is not None:
            self.search_var.trace_remove("write", self._search_trace)
            self._search_trace = None

    def _update_status(self):
        self.status.configure(text=t(
            self._status_key, count=f"{self.source.max_lines:,}".replace(",", " "),
            shown=len(self._visible_entries), total=len(self._entries),
        ))

    def _update_empty(self):
        filtered = self._filtered() and bool(self._entries)
        self._empty_label.configure(text=t("logs.no_matches" if filtered else "logs.empty"))
        self._empty_hint.configure(text=t("logs.no_matches_hint"))
        if self._visible_entries:
            self.empty_state.grid_remove()
        else:
            if filtered:
                self._empty_hint.grid(row=2, column=0, pady=(8, 0))
            else:
                self._empty_hint.grid_remove()
            self.empty_state.grid()

    def _copy(self, text):
        if not text:
            return
        try:
            self.text.clipboard_clear()
            self.text.clipboard_append(text)
            self._status_key = "logs.copy_success"
        except TclError:
            self._status_key = "logs.copy_failed"
        self.status.configure(text=t(self._status_key))

    def copy_all(self):
        self._copy(self.text.get("1.0", "end-1c").rstrip("\n"))

    def _keyboard(self, event):
        key = event.keysym.lower()
        if key == "a" or event.keycode == 65:
            self.text.tag_add("sel", "1.0", "end-1c")
            return "break"
        if key == "c" or event.keycode == 67:
            try:
                self._copy(self.text.get("sel.first", "sel.last"))
            except TclError:
                pass
            return "break"
