import logging
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError

from proxy.utils import SensitiveDataFormatter
from utils.live_logs import LiveLogHandler


class LiveLogHandlerTest(unittest.TestCase):
    def test_multiline_history_is_bounded_and_slow_reader_is_reset(self):
        handler = LiveLogHandler(max_lines=3)
        handler.handle(logging.makeLogRecord({"msg": "first\nsecond"}))
        cursor, lines, reset = handler.read_since()
        self.assertEqual(lines, ("first", "second"))
        self.assertTrue(reset)
        handler.handle(logging.makeLogRecord({"msg": "third\nfourth\nfifth\nsixth"}))
        next_cursor, lines, reset = handler.read_since(cursor)
        self.assertEqual(lines, ("fourth", "fifth", "sixth"))
        self.assertTrue(reset)
        self.assertEqual(handler.read_since(next_cursor), (next_cursor, (), False))

    def test_background_producers_can_be_read_without_losing_or_duplicating_lines(self):
        handler = LiveLogHandler(max_lines=1000)

        def produce(producer):
            for index in range(100):
                handler.handle(logging.makeLogRecord({"msg": f"{producer}:{index}"}))

        with ThreadPoolExecutor(max_workers=4) as workers:
            futures = [workers.submit(produce, producer) for producer in range(4)]
            cursor, first_batch, _ = handler.read_since()
            for future in futures:
                future.result()
        _, second_batch, reset = handler.read_since(cursor)
        all_lines = first_batch + second_batch
        self.assertFalse(reset)
        self.assertEqual(len(all_lines), 400)
        self.assertEqual(len(set(all_lines)), 400)

    def test_redaction_filter_cannot_change_record_for_other_handlers(self):
        handler = LiveLogHandler()

        class Redact(logging.Filter):
            def filter(self, record):
                record.msg = "redacted"
                record.args = ()
                return True

        handler.addFilter(Redact())
        original = logging.makeLogRecord({"msg": "value %s", "args": ("secret",)})
        handler.handle(original)
        self.assertEqual(original.getMessage(), "value secret")
        self.assertEqual(handler.read_since()[1], ("redacted",))

    def test_structured_multiline_entries_preserve_level_timestamp_and_record_group(self):
        handler = LiveLogHandler()
        handler.setFormatter(logging.Formatter("%(levelname)-8s %(name)s: %(message)s"))
        original = logging.makeLogRecord({
            "name": "tg-worker", "created": 1234.5,
            "levelno": logging.WARNING, "levelname": "WARNING",
            "msg": "INFO in message\n\nERROR in continuation", "args": (),
        })
        handler.handle(original)

        cursor, entries, reset = handler.read_entries_since()
        self.assertEqual(cursor, 3)
        self.assertTrue(reset)
        self.assertEqual(tuple(entry.seq for entry in entries), (1, 2, 3))
        self.assertEqual(tuple(entry.message for entry in entries),
                         ("INFO in message", "", "ERROR in continuation"))
        self.assertEqual(tuple(entry.continuation for entry in entries), (False, True, True))
        for entry in entries:
            self.assertEqual(entry.created, 1234.5)
            self.assertEqual(entry.levelno, logging.WARNING)
            self.assertEqual(entry.levelname, "WARNING")
            self.assertEqual(entry.name, "tg-worker")
            self.assertEqual(entry.record_seq, 1)
        self.assertEqual(handler.read_since(),
                         (cursor, tuple(entry.text for entry in entries), reset))
        self.assertEqual(tuple(handler._lines), tuple((entry.seq, entry.text) for entry in entries))
        self.assertEqual(handler.read_entries_since(cursor), (cursor, (), False))
        with self.assertRaises(FrozenInstanceError):
            entries[0].message = "changed"

    def test_structured_cursors_reset_after_eviction_and_for_future_cursor(self):
        handler = LiveLogHandler(max_lines=3)
        handler.handle(logging.makeLogRecord({"msg": "one\ntwo"}))
        old_cursor, _, _ = handler.read_entries_since()
        handler.handle(logging.makeLogRecord({"msg": "three\nfour\nfive\nsix"}))
        cursor, entries, reset = handler.read_entries_since(old_cursor)
        self.assertTrue(reset)
        self.assertEqual(cursor, 6)
        self.assertEqual(tuple(entry.seq for entry in entries), (4, 5, 6))
        self.assertEqual(tuple(entry.message for entry in entries), ("four", "five", "six"))
        self.assertTrue(all(entry.record_seq == 3 and entry.continuation for entry in entries))
        self.assertEqual(handler.read_entries_since(100), (cursor, entries, True))
        self.assertEqual(handler.read_entries_since(3), (cursor, entries, False))
        self.assertEqual(handler.read_entries_since(5), (cursor, entries[-1:], False))

    def test_minimal_legacy_record_defaults_to_info_without_mutating_record(self):
        handler = LiveLogHandler()
        original = logging.makeLogRecord({"msg": "legacy line"})
        original_levelname = original.levelname
        handler.handle(original)
        entry = handler.read_entries_since()[1][0]
        self.assertEqual(entry.levelno, logging.INFO)
        self.assertEqual(entry.levelname, "INFO")
        self.assertEqual(entry.message, "legacy line")
        self.assertIsNone(original.levelno)
        self.assertEqual(original.levelname, original_levelname)

    def test_default_retention_limit_counts_physical_lines(self):
        handler = LiveLogHandler()
        for _ in range(2):
            handler.handle(logging.makeLogRecord({"msg": "\n".join(str(i) for i in range(1100))}))
        cursor, entries, _ = handler.read_entries_since()
        self.assertEqual(handler.max_lines, 2000)
        self.assertEqual(cursor, 2200)
        self.assertEqual(len(entries), 2000)
        self.assertEqual(entries[0].seq, 201)
        self.assertEqual(entries[-1].seq, 2200)
        self.assertEqual(len(handler.read_since()[1]), 2000)

    def test_structured_concurrent_emits_keep_each_multiline_record_together(self):
        handler = LiveLogHandler(max_lines=1000)

        def produce(producer):
            for index in range(100):
                # Direct emit also needs atomic append/sequence assignment.
                handler.emit(logging.makeLogRecord({"msg": f"{producer}:{index}\ncontinued"}))

        with ThreadPoolExecutor(max_workers=4) as workers:
            futures = [workers.submit(produce, producer) for producer in range(4)]
            cursor, first_batch, _ = handler.read_entries_since()
            for future in futures:
                future.result()
        final_cursor, second_batch, reset = handler.read_entries_since(cursor)
        entries = first_batch + second_batch
        self.assertFalse(reset)
        self.assertEqual(final_cursor, 800)
        self.assertEqual(tuple(entry.seq for entry in entries), tuple(range(1, 801)))
        self.assertEqual(len(set(entry.message for entry in entries[::2])), 400)
        for first, continuation in zip(entries[::2], entries[1::2]):
            self.assertEqual(first.record_seq, first.seq)
            self.assertEqual(continuation.record_seq, first.seq)
            self.assertFalse(first.continuation)
            self.assertTrue(continuation.continuation)

    def test_all_retained_text_is_redacted_and_original_record_is_unchanged(self):
        secret = "0123456789abcdef0123456789abcdef"
        token = "private.helper.token"
        handler = LiveLogHandler()
        handler.setFormatter(SensitiveDataFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            secrets=lambda: (secret, token),
        ))
        try:
            raise RuntimeError(f"Rejected {token} and {secret}")
        except RuntimeError:
            original = logging.makeLogRecord({
                "name": "worker-" + token, "created": 1234.5,
                "levelno": logging.ERROR, "levelname": "ERROR-" + secret,
                "msg": "URL secret=dd%s\nBearer %s", "args": (secret, token),
                "exc_info": sys.exc_info(), "stack_info": f"Stack contains {secret}",
            })
        original_message, original_exception = original.getMessage(), original.exc_info
        handler.handle(original)
        _, entries, _ = handler.read_entries_since()

        self.assertGreater(len(entries), 3)
        self.assertEqual(entries[0].message, "URL secret=<redacted>")
        self.assertEqual(entries[1].message, "Bearer <redacted>")
        self.assertIn("Traceback", "\n".join(entry.message for entry in entries))
        self.assertNotIn(secret, repr(entries))
        self.assertNotIn(token, repr(entries))
        self.assertTrue(all(entry.levelno == logging.ERROR for entry in entries))
        self.assertTrue(all(entry.levelname == "ERROR-<redacted>" for entry in entries))
        self.assertEqual(original.getMessage(), original_message)
        self.assertIs(original.exc_info, original_exception)
        self.assertIsNone(original.exc_text)
        self.assertEqual(original.name, "worker-" + token)
        self.assertEqual(original.levelname, "ERROR-" + secret)
        self.assertEqual(original.args, (secret, token))

    def test_nonprefix_formatter_falls_back_to_safe_formatted_text(self):
        handler = LiveLogHandler()
        handler.setFormatter(SensitiveDataFormatter("%(message)s :: %(levelname)s"))
        handler.handle(logging.makeLogRecord({
            "msg": "secret=never-retain-this", "levelno": logging.WARNING,
            "levelname": "WARNING", "name": "worker",
        }))
        entry = handler.read_entries_since()[1][0]
        self.assertEqual(entry.text, "secret=<redacted> :: WARNING")
        self.assertEqual(entry.message, entry.text)


if __name__ == "__main__":
    unittest.main()
