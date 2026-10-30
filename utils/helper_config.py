"""Resolve the helper switch without discarding its saved transport settings."""
from __future__ import annotations


_HELPER_MODES = ("tls-pin", "legacy")


def helper_is_enabled(config: dict) -> bool:
    """Keep old active configurations working until the switch is persisted."""
    if "helper_enabled" in config:
        # JSON stores a boolean. Malformed strings such as "false" must never
        # turn an explicitly disabled helper into an active connection.
        return config["helper_enabled"] is True
    return config.get("helper_mode", "direct") in _HELPER_MODES


def effective_helper_mode(config: dict) -> str:
    """Choose the runtime route; enabling an old direct config defaults to TLS."""
    if not helper_is_enabled(config):
        return "direct"
    mode = config.get("helper_mode", "direct")
    return mode if mode in _HELPER_MODES else "tls-pin"
