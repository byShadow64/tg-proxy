"""Bounded local secret input; values are never put into error messages."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path


def validate_secret(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", value.strip()):
        raise ValueError("Secret must contain exactly 32 hexadecimal characters")
    return value.strip().lower()


def read_secret_file(filename):
    path = Path(filename).expanduser()
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or getattr(before, "st_file_attributes", 0) & 0x400:
        raise ValueError("Secret file must be an ordinary private file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 128
                or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError("Secret file must be a small ordinary file")
        if os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("Secret file must be owned by the current user with mode 0600 or 0400")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = None
            raw = source.read(129)
        if len(raw) > 128:
            raise ValueError("Secret file exceeds its size limit")
        try:
            return validate_secret(raw.decode("ascii"))
        except UnicodeError:
            raise ValueError("Secret file must contain 32 hexadecimal characters") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def redact_secret_arguments(arguments):
    """Remove legacy values from later diagnostics/child argv; OS history cannot be undone."""
    following = False
    for index, value in enumerate(arguments):
        if following:
            arguments[index] = "<redacted>"
            following = False
        elif value == "--secret":
            following = True
        elif value.startswith("--secret="):
            arguments[index] = "--secret=<redacted>"
