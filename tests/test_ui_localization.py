"""Exercise the actual desktop widgets with synthetic state, without networking."""
import logging
import json
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tkinter import TclError

from ui import ctk_tray_ui, dashboard, helper_settings, settings_form
from ui.ctk_theme import apply_ctk_appearance, ctk_theme_for_platform
from ui.i18n import get_config_language, set_language, t
from ui.log_viewer import LogViewer
from utils.default_config import default_tray_config
from utils.live_logs import LiveLogHandler


_APP = None


def setUpModule():
    import customtkinter as ctk

    global _APP
    try:
        _APP = ctk.CTk()
    except TclError as exc:
        raise unittest.SkipTest(f"Native Tk display is unavailable: {exc}") from exc
    _APP.withdraw()


def tearDownModule():
    if _APP is not None:
        _APP.destroy()


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


class CatalogEncodingTest(unittest.TestCase):
    def test_english_catalog_has_no_cyrillic_mojibake_and_keeps_native_language_name(self):
        catalog = json.loads((Path(__file__).resolve().parents[1] / "ui" / "i18n" / "en.json")
                             .read_text(encoding="utf-8"))
        self.assertEqual(catalog["language.ru"], "\u0420\u0443\u0441\u0441\u043a\u0438\u0439")
        for key, value in catalog.items():
            with self.subTest(key=key):
                self.assertNotIn("\ufffd", value)
                if key != "language.ru":
                    self.assertIsNone(re.search(r"[\u0400-\u04ff]", value), ascii(value))


class NativeUiTest(unittest.TestCase):
    def setUp(self):
        import customtkinter as ctk

        self.ctk = ctk
        self.addCleanup(set_language, get_config_language())
        self.addCleanup(ctk.set_appearance_mode, ctk.get_appearance_mode())
        self.app = _APP
        self.theme = ctk_theme_for_platform()
        apply_ctk_appearance(ctk, "light")

    def window(self):
        window = self.ctk.CTkToplevel(self.app)
        window.withdraw()
        self.addCleanup(lambda: window.destroy() if window.winfo_exists() else None)
        return window

    def pump(self):
        # Windows maps Toplevel windows after idle geometry work.
        self.app.update()
        ready = self.ctk.BooleanVar(master=self.app, value=False)
        self.app.after(40, lambda: ready.set(True))
        self.app.wait_variable(ready)
        self.app.update()

    def show(self, root, size):
        root.geometry(f"{size}+10000+10000")
        root.deiconify()
        self.pump()

    def assertInside(self, widget, container):
        self.assertTrue(widget.winfo_ismapped(), widget)
        x = widget.winfo_rootx() - container.winfo_rootx()
        y = widget.winfo_rooty() - container.winfo_rooty()
        self.assertGreaterEqual(x, -1)
        self.assertGreaterEqual(y, -1)
        self.assertLessEqual(x + widget.winfo_width(), container.winfo_width() + 1)
        self.assertLessEqual(y + widget.winfo_height(), container.winfo_height() + 1)

    def button(self, root, key):
        return next(widget for widget in descendants(root)
                    if isinstance(widget, self.ctk.CTkButton) and widget.cget("text") == t(key))

    def assertEnglish(self, root):
        strings = [root.title()]
        for widget in descendants(root):
            if isinstance(widget, (self.ctk.CTkLabel, self.ctk.CTkButton)):
                strings.append(widget.cget("text"))
            elif isinstance(widget, self.ctk.CTkEntry):
                strings.append(widget.cget("placeholder_text") or "")
        self.assertFalse(any(re.search("[А-Яа-яЁё]", text) for text in strings), strings)
        self.assertFalse(any(re.match(r"(?:dashboard|logs|helper|settings|first_run)\.", text)
                             for text in strings), strings)


class NativeDashboardTest(NativeUiTest):
    def test_navigation_status_resize_theme_and_runtime_language_keep_log_selection(self):
        set_language("ru")
        root = self.window()
        source = LiveLogHandler()
        source.handle(logging.makeLogRecord({"msg": "Original log line"}))
        state = SimpleNamespace(
            connections_active=7, connections_total=1234, bytes_up=4096, bytes_down=8192,
            connections_helper=1, connections_ws=2, connections_cfproxy=3, connections_tcp_fallback=4)
        running = [True]
        actions = {key: mock.Mock() for key in ("telegram", "settings", "restart", "close")}
        with mock.patch.object(dashboard, "stats", state):
            view = dashboard.DashboardView(
                self.ctk, root, self.theme,
                {"host": "127.0.0.1", "port": 1443, "secret": "1" * 32},
                running=lambda: running[0], on_telegram=actions["telegram"],
                on_settings=actions["settings"],
                on_restart=actions["restart"], config_path="synthetic/config.json",
                on_close=actions["close"], log_source=source)
            self.addCleanup(lambda: view.close() if not view.closed else None)

            def refresh():
                if view._refresh_id is not None:
                    root.after_cancel(view._refresh_id)
                view._last_stats_update = 0
                view.refresh()
                self.pump()

            self.show(root, "1080x760")
            self.assertEqual(view.status.cget("text"), t("dashboard.running"))
            self.assertEqual(view.metrics["connections"].cget("text"), "7")
            self.assertEqual(view.metric_details["connections"].cget("text"),
                             t("dashboard.total_connections", count="1 234"))
            navigation = [widget.cget("text") for widget in descendants(root)
                          if isinstance(widget, self.ctk.CTkButton)]
            self.assertNotIn(t("dashboard.own_server"), navigation)
            self.assertIn(t("settings.title"), navigation)
            for widget, key in ((view.telegram_button, "telegram"), (view.settings_button, "settings"),
                                (view.restart_button, "restart")):
                widget.invoke()
                actions[key].assert_called_once()
            view.copy_button.invoke()
            self.assertEqual(root.clipboard_get(),
                             "tg://proxy?server=127.0.0.1&port=1443&secret=dd" + "1" * 32)
            view.logs_button.invoke()
            self.pump()
            self.assertTrue(view.logs_visible)
            self.assertEqual(view.page_title.cget("text"), t("logs.title"))
            self.assertEqual(view.logs_button.cget("fg_color"), self.theme.accent_soft)
            text, cursor = view.log_viewer.text, view.log_viewer.cursor
            rendered_log = text.get("1.0", "end-1c")
            self.assertIn("Original log line", rendered_log)
            text.tag_add("sel", "1.0", "1.8")
            selection = tuple(str(index) for index in text.tag_ranges("sel"))
            set_language("en")
            refresh()
            self.assertEnglish(root)
            self.assertEqual(view.log_viewer.copy_button.cget("text"), t("logs.copy_all"))
            self.assertEqual(view.log_viewer.status.cget("text"), t("logs.history", count="2 000"))
            self.assertIs(view.log_viewer.text, text)
            self.assertEqual(view.log_viewer.cursor, cursor)
            self.assertEqual(text.get("1.0", "end-1c"), rendered_log)
            self.assertEqual(tuple(str(index) for index in text.tag_ranges("sel")), selection)
            for appearance in ("light", "dark"):
                self.ctk.set_appearance_mode(appearance)
                for size in ("860x640", "1200x800"):
                    with self.subTest(appearance=appearance, size=size):
                        self.show(root, size)
                        for widget in (view.overview_button, view.logs_button, view.settings_button,
                                       view.log_viewer.copy_button,
                                       view.log_viewer.end_button, view.log_viewer.status):
                            self.assertInside(widget, root)
                        self.assertGreater(text.winfo_width(), 400)
                        self.assertGreater(text.winfo_height(), 200)
            running[0] = False
            refresh()
            self.assertEqual(view.status.cget("text"), t("dashboard.stopped"))
            self.assertEqual(view.connection_title.cget("text"), t("dashboard.offline"))
            self.assertEqual(view.telegram_button.cget("text"), t("dashboard.start_proxy"))
            view.telegram_button.invoke()
            self.assertEqual(actions["restart"].call_count, 2)
            actions["telegram"].assert_called_once()
            view.overview_button.invoke()
            self.pump()
            self.assertFalse(view.logs_visible)
            self.assertTrue(view.overview.winfo_ismapped())
            self.assertFalse(view.log_viewer.frame.winfo_ismapped())
            set_language("ru")
            refresh()
            self.assertEqual(view.page_title.cget("text"), t("dashboard.overview"))
            self.assertEqual(view.log_viewer.copy_button.cget("text"), t("logs.copy_all"))
            # A full IPv6 listener address must wrap instead of widening the
            # overview beyond its viewport at the smallest supported size.
            view.config["host"] = "2001:db8:85a3:8d3:1319:8a2e:370:7348"
            refresh()
            self.show(root, "860x640")
            self.assertInside(view.endpoint, root)
            self.assertInside(view.telegram_button, root)
            self.assertLessEqual(view.overview.winfo_width(),
                                 view.overview._parent_canvas.winfo_width() + 2)


class NativeLogViewerTest(NativeUiTest):
    def test_closing_during_debounced_search_cancels_pending_widget_work(self):
        root = self.window()
        view = LogViewer(self.ctk, root, self.theme, LiveLogHandler(), lambda: None)
        view.frame.pack(fill="both", expand=True)
        self.show(root, "640x520")
        view.search_var.set("Pending search")
        pending = view._search_after
        self.assertIsNotNone(pending)
        view.frame.destroy()
        self.assertIsNone(view._search_after)
        self.assertIsNone(view._search_trace)
        with self.assertRaises(TclError):
            self.app.tk.call("after", "info", pending)
        view.search_var.set("Detached search cannot schedule work on destroyed widgets")
        for _ in range(5):
            self.pump()

    def test_filters_redacted_multiline_events_colors_and_live_appends(self):
        from proxy.utils import SensitiveDataFormatter

        set_language("ru")
        root = self.window()
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)
        secret = "0123456789abcdef0123456789abcdef"
        source = LiveLogHandler()
        source.setFormatter(SensitiveDataFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s", secrets=lambda: (secret,)))

        def emit(level, message):
            source.handle(logging.LogRecord("tg-mtproto-proxy", level, __file__, 1, message, (), None))

        emit(logging.INFO, "ERROR is only a word here")
        emit(logging.ERROR, f"Соединение потеряно\nValueError: Bearer {secret}\nRetry later")
        emit(logging.WARNING, "Temporary warning")
        emit(logging.DEBUG, "Debug detail")
        view = LogViewer(self.ctk, root, self.theme, source, lambda: None,
                         show_back=False, show_header=False)
        view.frame.grid(row=0, column=0, sticky="nsew", padx=24, pady=24)
        self.show(root, "640x520")
        view.refresh()
        for widget in (view.level_menu, view.search_label, view.search_entry, view.clear_button):
            self.assertInside(widget, root)
        self.assertEqual(view.search_label.cget("text"), t("logs.search_label"))
        self.assertGreater(view.search_entry.winfo_width(), 140)

        view.set_filter(level="ERROR", query="VALUEERROR")
        visible = view.text.get("1.0", "end-1c")
        self.assertIn("Соединение потеряно", visible)
        self.assertIn("Retry later", visible)
        self.assertNotIn(secret, visible)
        self.assertNotIn("Temporary warning", visible)
        self.assertEqual(len(visible.splitlines()), 3)
        for line in range(1, 4):
            self.assertIn("row_ERROR", view.text.tag_names(f"{line}.0"))
        self.assertTrue(view.text.tag_ranges("level_ERROR"))
        view.copy_all()
        self.assertEqual(view.text.clipboard_get(), visible.rstrip("\n"))

        view.set_filter(level="INFO", query="error")
        self.assertTrue(view.text.tag_ranges("level_INFO"))
        self.assertFalse(view.text.tag_ranges("level_ERROR"))
        selected = view.text.search("ERROR is only a word here", "1.0")
        view.text.tag_add("sel", selected, f"{selected}+5c")
        rendered = view.text.get("1.0", "end-1c")
        old_cursor = view.cursor
        old_color = view.text.tag_cget("level_INFO", "foreground")
        self.ctk.set_appearance_mode("dark")
        set_language("en")
        view.refresh()
        self.assertEnglish(root)
        self.assertEqual(view.search_var.get(), "error")
        self.assertEqual(view.level_menu.get(), "INFO")
        self.assertEqual(view.text.get("1.0", "end-1c"), rendered)
        self.assertEqual(view.cursor, old_cursor)
        self.assertEqual(view.text.get("sel.first", "sel.last"), "ERROR")
        self.assertNotEqual(view.text.tag_cget("level_INFO", "foreground"), old_color)
        self.assertEqual(view.text.tag_cget("level_INFO", "foreground"), self.theme.accent[1])
        emit(logging.WARNING, "Hidden ERROR warning")
        emit(logging.INFO, "ERROR arrives while filtered")
        view.refresh()
        self.assertGreater(view.cursor, old_cursor)
        self.assertEqual(view.text.get("sel.first", "sel.last"), "ERROR")
        self.assertIn("arrives while filtered", view.text.get("1.0", "end-1c"))
        self.assertNotIn("Hidden ERROR warning", view.text.get("1.0", "end-1c"))
        self.assertEqual(len(view._visible_entries), 2)

        view.search_var.set("no matching phrase")
        for _ in range(4):
            self.pump()
        self.assertTrue(view.empty_state.winfo_ismapped())
        self.assertEqual(view._empty_label.cget("text"), t("logs.no_matches"))
        self.assertEqual(view.copy_button.cget("state"), "disabled")
        view.clear_button.invoke()
        self.assertEqual(len(view._visible_entries), len(source.read_entries_since()[1]))
        self.assertEqual(view.search_var.get(), "")
        self.assertEqual(view.level_menu.get(), t("logs.filter_all"))

    def test_eviction_keeps_retained_selection_and_drops_stale_search_results(self):
        root = self.window()
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)
        source = LiveLogHandler(max_lines=4)
        for index in range(4):
            source.handle(logging.makeLogRecord({"msg": f"Retained event {index}"}))
        view = LogViewer(self.ctk, root, self.theme, source, lambda: None,
                         show_back=False, show_header=False)
        view.frame.grid(row=0, column=0, sticky="nsew", padx=24, pady=24)
        self.show(root, "640x520")
        view.refresh()
        selected = view.text.search("Retained event 2", "1.0")
        view.text.tag_add("sel", selected, f"{selected}+16c")
        source.handle(logging.makeLogRecord({"msg": "Newest event 4"}))
        view.refresh()
        self.assertEqual(view.text.get("sel.first", "sel.last"), "Retained event 2")
        self.assertEqual(len(view.text.get("1.0", "end-1c").splitlines()), 4)
        self.assertNotIn("Retained event 0", view.text.get("1.0", "end-1c"))
        view.set_filter(query="Retained event 0")
        self.assertEqual(view._visible_entries, ())
        view.clear_filters()
        self.assertEqual(tuple(entry.message for entry in view._visible_entries),
                         ("Retained event 1", "Retained event 2", "Retained event 3", "Newest event 4"))

    def test_empty_history_limit_keyboard_copy_and_language_feedback(self):
        set_language("ru")
        root = self.window()
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)
        source = LiveLogHandler(max_lines=3)
        view = LogViewer(self.ctk, root, self.theme, source, lambda: None, show_back=False)
        view.frame.grid(row=0, column=0, sticky="nsew", padx=24, pady=24)
        self.show(root, "640x520")
        view.refresh()
        self.assertTrue(view.empty_state.winfo_ismapped())
        self.assertEqual(view.copy_button.cget("state"), "disabled")
        for index in range(5):
            source.handle(logging.makeLogRecord({"msg": f"Line {index}"}))
        view.refresh()
        self.pump()
        self.assertFalse(view.empty_state.winfo_ismapped())
        rendered = view.text.get("1.0", "end-1c")
        self.assertEqual(len(rendered.splitlines()), 3)
        for line, message in zip(rendered.splitlines(), ("Line 2", "Line 3", "Line 4")):
            self.assertTrue(line.endswith(message))
        view.copy_all()
        self.assertEqual(view.text.clipboard_get(), rendered.rstrip("\n"))
        self.assertEqual(view.status.cget("text"), t("logs.copy_success"))
        self.assertEqual(view._keyboard(SimpleNamespace(keysym="a", keycode=65)), "break")
        self.assertEqual(view.text.get("sel.first", "sel.last"), view.text.get("1.0", "end-1c"))
        view.text.tag_remove("sel", "1.0", "end")
        selected = view.text.search("Line 3", "1.0")
        view.text.tag_add("sel", selected, f"{selected}+6c")
        self.assertEqual(view._keyboard(SimpleNamespace(keysym="c", keycode=67)), "break")
        self.assertEqual(view.text.clipboard_get(), "Line 3")
        set_language("en")
        view.refresh()
        self.assertEnglish(root)
        self.assertEqual(view.status.cget("text"), t("logs.copy_success"))
        with mock.patch.object(view.text, "clipboard_clear", side_effect=TclError):
            view.copy_all()
        self.assertEqual(view.status.cget("text"), t("logs.copy_failed"))
        source.handle(logging.makeLogRecord({"msg": "Line 5"}))
        view.refresh()
        rendered = view.text.get("1.0", "end-1c")
        self.assertEqual(len(rendered.splitlines()), 3)
        self.assertNotIn("Line 2", rendered)
        self.assertIn("Line 5", rendered)

    def test_appending_does_not_steal_scroll_position_or_selection(self):
        root = self.window()
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)
        source = LiveLogHandler(max_lines=300)
        for index in range(150):
            source.handle(logging.makeLogRecord({"msg": f"Event {index:03d}"}))
        view = LogViewer(self.ctk, root, self.theme, source, lambda: None,
                         show_back=False, show_header=False)
        view.frame.grid(row=0, column=0, sticky="nsew", padx=24, pady=24)
        self.show(root, "640x520")
        view.refresh()
        view.text.yview_moveto(0.2)
        selected = view.text.search("Event 039", "1.0")
        view.text.tag_add("sel", selected, f"{selected}+9c")
        self.pump()
        before = view.text.yview()[0]
        source.handle(logging.makeLogRecord({"msg": "Appended while reading"}))
        view.refresh()
        self.pump()
        self.assertAlmostEqual(view.text.yview()[0], before, delta=0.02)
        self.assertEqual(view.text.get("sel.first", "sel.last"), "Event 039")
        view.end_button.invoke()
        self.pump()
        self.assertGreaterEqual(view.text.yview()[1], 0.995)
        source.handle(logging.makeLogRecord({"msg": "Follow this event"}))
        view.refresh()
        self.pump()
        self.assertGreaterEqual(view.text.yview()[1], 0.995)


class NativeHelperTest(NativeUiTest):
    def test_modes_validation_localization_and_fixed_footer(self):
        for language in ("ru", "en"):
            set_language(language)
            root = self.window()
            config = {"helper_mode": "tls-pin", "helper_host": "203.0.113.10"}
            with mock.patch.object(helper_settings.messagebox, "showerror") as error:
                helper_settings.build_helper_settings(
                    self.ctk, root, self.theme, config, save_config=mock.Mock(),
                    restart=mock.Mock(), on_saved=mock.Mock())
                self.show(root, "460x420")
                if language == "en":
                    self.assertEnglish(root)
                save = self.button(root, "helper.save_restart")
                self.assertInside(save, root)
                self.assertInside(self.button(root, "button.cancel"), root)
                fields = {widget.cget("placeholder_text"): widget
                          for widget in descendants(root) if isinstance(widget, self.ctk.CTkEntry)}
                port, fingerprint, token = (fields[t(f"helper.{key}_placeholder")]
                                            for key in ("port", "fingerprint", "token"))

                def replace(entry, value):
                    entry.delete(0, "end")
                    entry.insert(0, value)

                replace(port, "bad")
                save.invoke()
                self.assertEqual(error.call_args.args[1], t("validation.bad_port"))
                replace(port, "8444")
                save.invoke()
                self.assertEqual(error.call_args.args[1], t("helper.bad_fingerprint"))
                replace(fingerprint, "a" * 64)
                save.invoke()
                self.assertEqual(error.call_args.args[1], t("helper.token_required"))
                replace(token, "synthetic-test-token")
                with mock.patch.object(helper_settings, "protect_token", side_effect=RuntimeError("test error")):
                    save.invoke()
                self.assertEqual(error.call_args.args[1], t("helper.protect_failed", error="test error"))
                self.assertNotIn("helper_token_dpapi", config)
                scroll = next(widget for widget in descendants(root)
                              if isinstance(widget, self.ctk.CTkScrollableFrame))
                scroll._parent_canvas.yview_moveto(1)
                self.pump()
                self.assertInside(token, scroll._parent_canvas)
                menu = next(widget for widget in descendants(root)
                            if isinstance(widget, self.ctk.CTkOptionMenu))
                for mode in ("direct", "legacy", "tls-pin"):
                    label = t(f"helper.mode.{mode}")
                    menu.set(label)
                    menu.cget("command")(label)
                    self.assertEqual(port.cget("state"), "disabled" if mode == "direct" else "normal")
                    self.assertEqual(token.cget("state"), "normal" if mode == "tls-pin" else "disabled")
                    self.assertEqual(port.get(), "8443" if mode == "legacy" else "8444")
            root.destroy()


class NativeSettingsAndOnboardingTest(NativeUiTest):
    def test_settings_tabs_keep_values_and_footer_reachable_in_both_languages(self):
        for language in ("ru", "en"):
            set_language(language)
            root = self.window()
            frame = self.ctk.CTkFrame(root, fg_color="transparent")
            frame.pack(fill="both", expand=True, padx=24, pady=24)
            content, footer = ctk_tray_ui.tray_settings_scroll_and_footer(self.ctk, frame, self.theme)
            defaults = default_tray_config()
            defaults.update(language=language, secret="a" * 32)
            saved, cancelled = mock.Mock(), mock.Mock()
            form = settings_form.install_tray_config_form(
                self.ctk, content, self.theme, dict(defaults), defaults, show_autostart=True)
            ctk_tray_ui.install_tray_config_buttons(
                self.ctk, footer, self.theme, on_save=saved, on_cancel=cancelled)
            self.show(root, "560x560")
            navigation = next(widget for widget in descendants(root)
                              if isinstance(widget, self.ctk.CTkSegmentedButton))
            self.assertInside(navigation, root)
            if language == "en":
                self.assertEnglish(root)
            for key in ("connection", "routes", "application", "advanced"):
                label = t(f"settings.tab.{key}")
                navigation.set(label)
                navigation.cget("command")(label)
                self.pump()
                pages = [widget for widget in descendants(root)
                         if isinstance(widget, self.ctk.CTkScrollableFrame)
                         and widget._parent_frame.winfo_ismapped()]
                self.assertEqual(len(pages), 1)
                self.assertInside(pages[0]._parent_canvas, root)
                for action in (self.button(root, "button.save"), self.button(root, "button.cancel")):
                    self.assertInside(action, root)
            self.assertEqual(form.secret_var.get(), "a" * 32)
            secret_entry = next(widget for widget in descendants(root)
                                if isinstance(widget, self.ctk.CTkEntry)
                                and widget.cget("textvariable") is form.secret_var)
            self.assertEqual(secret_entry.cget("show"), "•")
            self.button(root, "button.show").invoke()
            self.assertEqual(secret_entry.cget("show"), "")
            self.button(root, "settings.regenerate").invoke()
            self.assertRegex(form.secret_var.get(), r"^[0-9a-f]{32}$")
            self.assertNotEqual(form.secret_var.get(), "a" * 32)
            self.assertEqual(secret_entry.cget("show"), "•")
            form.secret_var.set("a" * 32)
            validated = settings_form.validate_config_form(form, defaults, include_autostart=True)
            self.assertIsInstance(validated, dict)
            self.assertEqual(validated["secret"], "a" * 32)
            self.assertEqual(validated["language"], language)
            self.button(root, "button.save").invoke()
            self.button(root, "button.cancel").invoke()
            saved.assert_called_once()
            cancelled.assert_called_once()
            root.destroy()

    def test_first_run_manual_values_and_actions_are_accessible(self):
        for language in ("ru", "en"):
            set_language(language)
            root = self.window()
            done = mock.Mock()
            ctk_tray_ui.populate_first_run_window(
                self.ctk, root, self.theme, host="127.0.0.1", port=1443,
                secret="f" * 32, on_done=done)
            self.show(root, "600x560")
            if language == "en":
                self.assertEnglish(root)
            connect, later = self.button(root, "first_run.connect"), self.button(root, "first_run.later")
            self.assertInside(connect, root)
            self.assertInside(later, root)
            entries = [widget for widget in descendants(root) if isinstance(widget, self.ctk.CTkEntry)]
            self.assertTrue(all(not widget.winfo_ismapped() for widget in entries))
            self.button(root, "first_run.manual_toggle").invoke()
            self.pump()
            scroll = next(widget for widget in descendants(root)
                          if isinstance(widget, self.ctk.CTkScrollableFrame))
            scroll._parent_canvas.yview_moveto(1)
            self.pump()
            self.assertEqual([widget.get() for widget in entries], ["127.0.0.1", "1443", "dd" + "f" * 32])
            self.assertTrue(all(widget.cget("state") == "readonly" for widget in entries))
            self.assertInside(entries[-1], scroll._parent_canvas)
            self.assertInside(connect, root)
            connect.invoke()
            later.invoke()
            self.assertEqual(done.call_args_list, [mock.call(True), mock.call(False)])
            root.destroy()


if __name__ == "__main__":
    unittest.main()
