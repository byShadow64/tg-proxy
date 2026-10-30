"""Shared construction of the rotating log file handler.

Centralizes the rotation invariant so both the tray and the CLI log paths
behave identically and the file can never grow without bound (issue #885).

A ``RotatingFileHandler`` only rotates when ``backupCount >= 1``: CPython's
``doRollover`` skips the entire rotation block when ``backupCount == 0``, so
``maxBytes`` is silently ignored and the active file grows forever. We force
at least one backup here regardless of caller input.
"""

from __future__ import annotations

import logging.handlers


_MIN_BYTES = 32 * 1024
_MIN_BACKUPS = 1
LOG_HANDLER_ROLE = "_tg_proxy_log_role"


def log_size_limit(log_max_mb: float) -> int:
    """Keep the same minimum size when creating or updating a log handler."""
    return max(_MIN_BYTES, int(log_max_mb * 1024 * 1024))


def apply_logging_verbosity(verbose: bool) -> None:
    """Change future app records without replacing handlers or their history.

    Root logger levels are not checked again for records propagated by child
    loggers. Every managed destination therefore needs its own threshold too.
    Leave handlers belonging to the embedding process or libraries untouched.
    """
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    for handler in root.handlers[:]:
        if getattr(handler, LOG_HANDLER_ROLE, None) in ("live", "file", "console"):
            handler.setLevel(level)
    root.setLevel(level)


def build_log_handler(
    path: str,
    log_max_mb: float = 5,
    backups: int = 1,
) -> logging.handlers.RotatingFileHandler:
    """Create a RotatingFileHandler that actually rotates.

    ``backups`` is clamped to at least 1 so rotation is always active, and
    ``maxBytes`` keeps a small floor so a misconfigured tiny size can't cause
    rotation on every line.
    """
    max_bytes = log_size_limit(log_max_mb)
    backup_count = max(_MIN_BACKUPS, int(backups))
    return logging.handlers.RotatingFileHandler(
        path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
