"""Verbosity changes must apply to every app sink immediately after Save."""
import io
import logging
import logging.handlers
import tempfile
import unittest
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock, patch

from proxy.config import ProxyConfig
from ui import settings_dialog
from utils import logging_setup, tray_common
from utils.default_config import default_tray_config
from utils.live_logs import LiveLogHandler


class LoggingLevelsTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.path = self.directory / "proxy.log"
        self.console = io.StringIO()
        self.history = LiveLogHandler()
        self.root = logging.getLogger()
        self.old_handlers, self.old_level = self.root.handlers[:], self.root.level
        self.root.handlers = []
        self.inherited = logging.getLogger("tg-proxy-test-inherited")
        self.explicit = logging.getLogger("tg-proxy-test-explicit")
        self.old_logger_levels = {logger: logger.level for logger in (
            self.inherited, self.explicit, logging.getLogger("asyncio"))}
        self.inherited.setLevel(logging.NOTSET)
        self.explicit.setLevel(logging.DEBUG)
        for target, value in (
            ("ensure_dirs", Mock()), ("LOG_FILE", self.path),
            ("live_logs", self.history), ("IS_FROZEN", False),
            ("proxy_config", ProxyConfig(secret="a" * 32, helper_token="synthetic-token")),
        ):
            self.stack.enter_context(patch.object(tray_common, target, value))
        self.stack.enter_context(patch("sys.stdout", self.console))

    def tearDown(self):
        for handler in self.root.handlers[:]:
            self.root.removeHandler(handler)
            handler.close()
        self.root.handlers = self.old_handlers
        self.root.setLevel(self.old_level)
        for logger, level in self.old_logger_levels.items():
            logger.setLevel(level)
        self.stack.close()

    def outputs(self):
        for handler in self.root.handlers:
            handler.flush()
        return (self.path.read_text(encoding="utf-8"),
                "\n".join(self.history.read_since()[1]), self.console.getvalue())

    def test_explicit_debug_child_cannot_bypass_nonverbose_app_handlers(self):
        tray_common.setup_logging(verbose=False)
        self.explicit.debug("hidden-child-debug")
        self.explicit.info("visible-child-info")
        self.explicit.warning("visible-child-warning")
        self.explicit.error("visible-child-error")
        for output in self.outputs():
            self.assertNotIn("hidden-child-debug", output)
            self.assertIn("visible-child-info", output)
            self.assertIn("visible-child-warning", output)
            self.assertIn("visible-child-error", output)

    def test_false_true_false_updates_existing_sinks_and_keeps_old_history(self):
        tray_common.setup_logging(verbose=False)
        self.inherited.debug("hidden-initial-inherited")
        self.explicit.debug("hidden-initial-explicit")
        logging_setup.apply_logging_verbosity(True)
        self.inherited.debug("visible-inherited-debug")
        self.explicit.debug("visible-explicit-debug")
        self.explicit.debug("Credentials secret=%s token=%s", "a" * 32, "synthetic-token")
        old_cursor = self.history.read_since()[0]
        logging_setup.apply_logging_verbosity(False)
        self.inherited.debug("hidden-final-inherited")
        self.explicit.debug("hidden-final-explicit")
        self.inherited.info("visible-final-info")
        for output in self.outputs():
            self.assertIn("visible-inherited-debug", output)
            self.assertIn("visible-explicit-debug", output)
            self.assertIn("visible-final-info", output)
            self.assertIn("<redacted>", output)
            self.assertNotIn("a" * 32, output)
            self.assertNotIn("synthetic-token", output)
            for hidden in ("hidden-initial-inherited", "hidden-initial-explicit",
                           "hidden-final-inherited", "hidden-final-explicit"):
                self.assertNotIn(hidden, output)
        cursor, new_lines, reset = self.history.read_since(old_cursor)
        self.assertFalse(reset)
        self.assertGreater(cursor, old_cursor)
        self.assertEqual(len(new_lines), 1)
        self.assertIn("visible-final-info", new_lines[0])

    def test_repeated_setup_reuses_handlers_and_updates_rotation_limit(self):
        tray_common.setup_logging(verbose=True, log_max_mb=1)
        original_file = next(handler for handler in self.root.handlers
                             if isinstance(handler, logging.handlers.RotatingFileHandler))
        self.inherited.debug("history-survives-setup")
        cursor = self.history.read_since()[0]
        tray_common.setup_logging(verbose=False, log_max_mb=0.01)
        files = [handler for handler in self.root.handlers
                 if isinstance(handler, logging.handlers.RotatingFileHandler)]
        self.assertEqual(files, [original_file])
        self.assertEqual(len(self.root.handlers), 3)
        self.assertEqual(original_file.maxBytes, 32 * 1024)
        self.assertEqual(original_file.backupCount, 1)
        self.assertEqual(self.history.read_since(cursor), (cursor, (), False))
        for index in range(70):
            self.inherited.info("rotation %s %s", index, "x" * 1000)
        self.inherited.warning("unique-tail-marker")
        for handler in self.root.handlers:
            handler.flush()
        self.assertTrue(self.path.with_name("proxy.log.1").exists())
        combined = self.path.read_text(encoding="utf-8") + self.path.with_name("proxy.log.1").read_text(encoding="utf-8")
        self.assertEqual(combined.count("unique-tail-marker"), 1)
        self.assertLessEqual(self.path.stat().st_size, original_file.maxBytes)
        self.assertFalse(self.path.with_name("proxy.log.2").exists())

    def test_changed_log_path_closes_old_file_and_preserves_unrelated_handlers(self):
        tray_common.setup_logging(verbose=True)
        old_file = next(handler for handler in self.root.handlers
                        if isinstance(handler, logging.handlers.RotatingFileHandler))
        external = logging.StreamHandler(io.StringIO())
        external.setLevel(logging.ERROR)
        self.root.addHandler(external)
        second_path = self.directory / "second.log"
        with patch.object(tray_common, "LOG_FILE", second_path):
            tray_common.setup_logging(verbose=False)
        self.assertNotIn(old_file, self.root.handlers)
        self.assertIsNone(old_file.stream)
        self.assertIn(external, self.root.handlers)
        self.assertEqual(external.level, logging.ERROR)
        self.inherited.info("written-to-new-file")
        self.assertIn("written-to-new-file", second_path.read_text(encoding="utf-8"))
        self.assertNotIn("written-to-new-file", self.path.read_text(encoding="utf-8"))

    def dialog(self, *, persist):
        current = default_tray_config()
        current.update(verbose=True, language="ru")
        restart, finish = Mock(), Mock()
        dialog = settings_dialog.SettingsDialog(
            ctk=Mock(), root=Mock(), widgets=Mock(helper_busy_var=None), config=current,
            defaults=deepcopy(current), persist=persist,
            refresh_menu=Mock(), finish=finish, restart=restart,
        )
        return dialog, current, restart, finish

    def test_successful_save_changes_logging_even_when_restart_is_declined(self):
        tray_common.setup_logging(verbose=True)
        self.inherited.debug("debug-before-successful-save")
        persist = Mock()
        dialog, current, restart, finish = self.dialog(persist=persist)
        with patch.object(settings_dialog, "validate_config_form", return_value={"verbose": False, "language": "ru"}), \
                patch.object(settings_dialog.messagebox, "askyesno", return_value=False) as restart_prompt:
            dialog.save()
        persist.assert_called_once()
        self.assertFalse(current["verbose"])
        restart_prompt.assert_called_once()
        restart.assert_not_called()
        finish.assert_called_once()
        self.explicit.debug("debug-after-successful-save")
        self.explicit.info("info-after-successful-save")
        for output in self.outputs():
            self.assertIn("debug-before-successful-save", output)
            self.assertNotIn("debug-after-successful-save", output)
            self.assertIn("info-after-successful-save", output)

    def test_failed_save_leaves_verbosity_and_config_unchanged(self):
        tray_common.setup_logging(verbose=True)
        dialog, current, restart, finish = self.dialog(persist=Mock(side_effect=OSError("synthetic failure")))
        with patch.object(settings_dialog, "validate_config_form", return_value={"verbose": False, "language": "ru"}), \
                patch.object(settings_dialog.messagebox, "showerror") as error:
            dialog.save()
        error.assert_called_once()
        self.assertTrue(current["verbose"])
        self.assertFalse(dialog.closed)
        restart.assert_not_called()
        finish.assert_not_called()
        self.explicit.debug("debug-after-failed-save")
        for output in self.outputs():
            self.assertIn("debug-after-failed-save", output)

    def test_successful_save_can_enable_debug_without_restarting_proxy(self):
        tray_common.setup_logging(verbose=False)
        dialog, current, restart, _ = self.dialog(persist=Mock())
        current["verbose"] = False
        with patch.object(settings_dialog, "validate_config_form", return_value={"verbose": True, "language": "ru"}), \
                patch.object(settings_dialog.messagebox, "askyesno", return_value=False):
            dialog.save()
        self.assertTrue(current["verbose"])
        restart.assert_not_called()
        self.inherited.debug("debug-enabled-after-save")
        for output in self.outputs():
            self.assertIn("debug-enabled-after-save", output)


if __name__ == "__main__":
    unittest.main()
