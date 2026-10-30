"""Filtering is driven by safe record metadata, never text-shaped severity."""
import logging
import unittest

from proxy.utils import SensitiveDataFormatter
from ui.log_viewer import filter_entries
from utils.live_logs import LiveLogHandler


def emit(handler, level, message, name="worker"):
    handler.handle(logging.LogRecord(name, level, __file__, 1, message, (), None))


class LogFilteringTest(unittest.TestCase):
    def test_levels_use_record_metadata_and_critical_belongs_to_errors(self):
        history = LiveLogHandler()
        emit(history, logging.INFO, "Text mentions ERROR and WARNING")
        emit(history, logging.WARNING, "INFO in a warning")
        emit(history, logging.ERROR, "Failure\nDEBUG in continuation")
        emit(history, logging.CRITICAL, "Fatal failure")
        emit(history, logging.DEBUG, "Debug details")
        entries = history.read_entries_since()[1]
        self.assertEqual(tuple(entry.message for entry in filter_entries(entries, "INFO")),
                         ("Text mentions ERROR and WARNING",))
        self.assertEqual(tuple(entry.message for entry in filter_entries(entries, "ERROR")),
                         ("Failure", "DEBUG in continuation", "Fatal failure"))
        self.assertEqual(tuple(entry.message for entry in filter_entries(entries, "DEBUG")),
                         ("Debug details",))

    def test_search_is_case_insensitive_and_keeps_the_complete_multiline_event(self):
        history = LiveLogHandler()
        emit(history, logging.ERROR, "Соединение потеряно\nTraceback\nValueError: details", name="helper")
        emit(history, logging.INFO, "Connection restored", name="helper")
        entries = history.read_entries_since()[1]
        error = entries[:3]
        self.assertEqual(filter_entries(entries, query="СОЕДИНЕНИЕ"), error)
        self.assertEqual(filter_entries(entries, query="valueerror"), error)
        self.assertEqual(filter_entries(entries, "ERROR", "HELPER"), error)
        self.assertEqual(filter_entries(entries, "WARNING", "helper"), ())
        self.assertEqual(filter_entries(entries, query="does not exist"), ())
        self.assertEqual(filter_entries(entries, query="   "), entries)

    def test_search_cannot_recover_redacted_credentials_or_evicted_lines(self):
        secret = "0123456789abcdef0123456789abcdef"
        history = LiveLogHandler(max_lines=3)
        history.setFormatter(SensitiveDataFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s", secrets=lambda: (secret,)))
        emit(history, logging.ERROR, f"Rejected Bearer {secret}\nRetry later")
        entries = history.read_entries_since()[1]
        self.assertEqual(filter_entries(entries, query=secret), ())
        self.assertEqual(tuple(entry.message for entry in filter_entries(entries, query="redacted")),
                         ("Rejected Bearer <redacted>", "Retry later"))
        emit(history, logging.INFO, "New event one\nNew event two\nNew event three")
        current = history.read_entries_since()[1]
        self.assertEqual(filter_entries(current, query="rejected"), ())
        self.assertEqual(len(filter_entries(current)), 3)


if __name__ == "__main__":
    unittest.main()
