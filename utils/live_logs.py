"""Bounded, thread-safe log history consumed by the Tk dashboard."""
from __future__ import annotations

import logging
from collections import deque
from copy import copy
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class LogEntry:
    """One formatted physical line, with the originating record's metadata.

    Text fields have already passed through the handler's formatter. Keep no
    raw message, format arguments or exception objects in the retained history.
    """

    seq: int
    created: float
    levelno: int
    levelname: str
    name: str
    text: str
    message: str
    record_seq: int = 0
    continuation: bool = False


class LiveLogHandler(logging.Handler):
    def __init__(self, max_lines: int = 2000):
        super().__init__()
        self.max_lines = max(1, max_lines)
        self._lines = deque(maxlen=self.max_lines)
        self._entries = deque(maxlen=self.max_lines)
        self._sequence = 0

    def handle(self, record: logging.LogRecord) -> bool:
        # Filters may redact record.msg; do not change what other handlers see.
        return super().handle(copy(record))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            source = copy(record)
            if isinstance(record.levelno, int):
                source.levelno = record.levelno
                source.levelname = record.levelname or logging.getLevelName(source.levelno)
            else:
                source.levelno, source.levelname = logging.INFO, "INFO"
            source.name = record.name or ""
            text = self.format(source)
            context = copy(source)
            context.msg, context.args = "", ()
            context.exc_info = context.exc_text = context.stack_info = None
            prefix = self.format(context)
            # Derive the compact body from safe formatted output, rather than
            # calling getMessage() and bypassing credential redaction. Exotic
            # formatters remain safe by falling back to the full rendered line.
            compact = self._without_prefix(text, prefix)
            context.msg = source.name
            name = self._without_prefix(self.format(context), prefix)
            context.msg = source.levelname
            levelname = self._without_prefix(self.format(context), prefix)
            lines = text.splitlines() or [""]
            messages = compact.splitlines() or [""]
            if len(messages) != len(lines):
                messages = lines
            self.acquire()
            try:
                record_seq = self._sequence + 1
                for index, (line, message) in enumerate(zip(lines, messages)):
                    self._sequence += 1
                    entry = LogEntry(
                        seq=self._sequence, created=source.created,
                        levelno=source.levelno, levelname=levelname,
                        name=name, text=line, message=message,
                        record_seq=record_seq, continuation=index > 0,
                    )
                    self._entries.append(entry)
                    self._lines.append((entry.seq, entry.text))
            finally:
                self.release()
        except Exception:
            self.handleError(record)

    @staticmethod
    def _without_prefix(text: str, prefix: str) -> str:
        if "\n" not in prefix and "\r" not in prefix and text.startswith(prefix):
            return text[len(prefix):]
        return text

    def read_entries_since(
        self, cursor: Optional[int] = None,
    ) -> Tuple[int, Tuple[LogEntry, ...], bool]:
        """Return safe structured lines; reset means the cursor was evicted."""
        self.acquire()
        try:
            first = self._entries[0].seq if self._entries else self._sequence + 1
            reset = cursor is None or cursor < first - 1 or cursor > self._sequence
            entries = tuple(entry for entry in self._entries
                            if reset or entry.seq > cursor)
            return self._sequence, entries, reset
        finally:
            self.release()

    def read_since(self, cursor: Optional[int] = None) -> Tuple[int, Tuple[str, ...], bool]:
        """Keep the original string-based history API for existing consumers."""
        self.acquire()
        try:
            first = self._lines[0][0] if self._lines else self._sequence + 1
            reset = cursor is None or cursor < first - 1 or cursor > self._sequence
            lines = tuple(line for sequence, line in self._lines
                          if reset or sequence > cursor)
            return self._sequence, lines, reset
        finally:
            self.release()


live_logs = LiveLogHandler()
