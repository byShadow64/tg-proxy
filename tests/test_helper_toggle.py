"""The helper switch changes the runtime route, keeping saved credentials."""
import unittest
from copy import deepcopy
from unittest.mock import patch

from proxy.config import ProxyConfig
from ui.settings import prepare_settings
from utils import tray_common
from utils.default_config import default_tray_config
from utils.helper_config import effective_helper_mode, helper_is_enabled


class HelperModeResolutionTest(unittest.TestCase):
    def test_new_and_direct_configurations_are_disabled_by_default(self):
        for config in ({}, {"helper_mode": "direct"}, default_tray_config()):
            with self.subTest(config=config):
                self.assertFalse(helper_is_enabled(config))
                self.assertEqual(effective_helper_mode(config), "direct")

    def test_missing_switch_preserves_existing_active_modes(self):
        for mode in ("tls-pin", "legacy"):
            config = {"helper_mode": mode}
            self.assertTrue(helper_is_enabled(config))
            self.assertEqual(effective_helper_mode(config), mode)
            self.assertNotIn("helper_enabled", config)

    def test_explicit_switch_controls_route_without_replacing_saved_mode(self):
        for mode in ("tls-pin", "legacy", "direct"):
            for enabled in (False, True):
                with self.subTest(mode=mode, enabled=enabled):
                    config = {"helper_mode": mode, "helper_enabled": enabled}
                    original = config.copy()
                    expected = (mode if mode != "direct" else "tls-pin") if enabled else "direct"
                    self.assertIs(helper_is_enabled(config), enabled)
                    self.assertEqual(effective_helper_mode(config), expected)
                    self.assertEqual(config, original)

    def test_unknown_mode_never_defaults_to_legacy(self):
        config = {"helper_enabled": True, "helper_mode": "unknown"}
        self.assertEqual(effective_helper_mode(config), "tls-pin")

    def test_malformed_non_boolean_switch_values_fail_closed(self):
        for value in (None, "false", "true", 0, 1, [], {}):
            with self.subTest(value=value):
                config = {"helper_enabled": value, "helper_mode": "legacy"}
                self.assertFalse(helper_is_enabled(config))
                self.assertEqual(effective_helper_mode(config), "direct")


class HelperSettingsChangeTest(unittest.TestCase):
    def test_disabling_an_old_active_mode_is_a_change_requiring_restart(self):
        for mode in ("tls-pin", "legacy"):
            with self.subTest(mode=mode):
                current = {
                    "helper_mode": mode, "helper_host": "203.0.113.10",
                    "helper_port": 8444 if mode == "tls-pin" else 8443,
                    "helper_fingerprint": "a" * 64,
                    "helper_token_dpapi": "synthetic-ciphertext",
                }
                original = deepcopy(current)
                change = prepare_settings(current, {"helper_enabled": False}, default_tray_config())
                self.assertEqual(change.changed_keys, frozenset({"helper_enabled"}))
                self.assertTrue(change.requires_restart)
                self.assertFalse(change.config["helper_enabled"])
                self.assertEqual(effective_helper_mode(change.config), "direct")
                for key, value in original.items():
                    self.assertEqual(change.config[key], value)
                self.assertEqual(current, original)

    def test_leaving_an_old_active_mode_enabled_does_not_require_restart(self):
        for mode in ("tls-pin", "legacy"):
            with self.subTest(mode=mode):
                current = {"helper_mode": mode}
                change = prepare_settings(current, {"helper_enabled": True}, default_tray_config())
                self.assertEqual(change.changed_keys, frozenset())
                self.assertFalse(change.requires_restart)
                self.assertTrue(change.config["helper_enabled"])
                self.assertEqual(effective_helper_mode(change.config), mode)
                self.assertNotIn("helper_enabled", current)

    def test_enabling_an_explicitly_disabled_helper_requires_restart(self):
        for mode in ("tls-pin", "legacy", "direct"):
            with self.subTest(mode=mode):
                current = {"helper_enabled": False, "helper_mode": mode}
                change = prepare_settings(current, {"helper_enabled": True}, default_tray_config())
                self.assertEqual(change.changed_keys, frozenset({"helper_enabled"}))
                self.assertTrue(change.requires_restart)
                self.assertTrue(change.config["helper_enabled"])
                self.assertEqual(change.config["helper_mode"], mode)
                self.assertFalse(current["helper_enabled"])


class HelperRuntimeSwitchTest(unittest.TestCase):
    def test_on_off_on_preserves_saved_transport_and_credentials(self):
        for mode in ("tls-pin", "legacy"):
            with self.subTest(mode=mode):
                config = default_tray_config()
                config.update(
                    helper_enabled=True, helper_mode=mode, helper_host="203.0.113.10",
                    helper_port=8444 if mode == "tls-pin" else 8443,
                    helper_fingerprint="a" * 64, helper_token_dpapi="synthetic-ciphertext",
                )
                stored = deepcopy(config)
                runtime = ProxyConfig()
                with patch.object(tray_common, "proxy_config", runtime), \
                        patch("utils.secure_storage.unprotect_token", return_value="synthetic-token") as unlock:
                    self.assertTrue(tray_common.apply_proxy_config(config))
                    self.assertEqual(runtime.helper_mode, mode)
                    self.assertEqual(runtime.helper_token, "synthetic-token" if mode == "tls-pin" else "")
                    unlock.reset_mock()
                    config["helper_enabled"] = False
                    self.assertTrue(tray_common.apply_proxy_config(config))
                    self.assertEqual(runtime.helper_mode, "direct")
                    self.assertEqual(runtime.helper_token, "")
                    unlock.assert_not_called()
                    config["helper_enabled"] = True
                    self.assertTrue(tray_common.apply_proxy_config(config))
                    self.assertEqual(runtime.helper_mode, mode)
                    self.assertEqual(config, stored)
                    self.assertEqual(runtime.helper_host, stored["helper_host"])
                    self.assertEqual(runtime.helper_port, stored["helper_port"])
                    self.assertEqual(runtime.helper_fingerprint, stored["helper_fingerprint"])
                    if mode == "tls-pin":
                        unlock.assert_called_once_with("synthetic-ciphertext")
                    else:
                        unlock.assert_not_called()

    def test_enabling_a_saved_direct_config_selects_tls_without_mutating_config(self):
        config = default_tray_config()
        config.update(helper_enabled=True, helper_host="203.0.113.10",
                      helper_fingerprint="b" * 64, helper_token_dpapi="synthetic-ciphertext")
        runtime = ProxyConfig()
        with patch.object(tray_common, "proxy_config", runtime), \
                patch("utils.secure_storage.unprotect_token", return_value="synthetic-token"):
            self.assertTrue(tray_common.apply_proxy_config(config))
        self.assertEqual(runtime.helper_mode, "tls-pin")
        self.assertEqual(runtime.helper_port, 8444)
        self.assertEqual(config["helper_mode"], "direct")

    def test_token_unlock_failure_keeps_tls_mode_without_legacy_downgrade(self):
        config = default_tray_config()
        config.update(helper_enabled=True, helper_mode="tls-pin",
                      helper_token_dpapi="synthetic-ciphertext")
        runtime = ProxyConfig()
        with patch.object(tray_common, "proxy_config", runtime), \
                patch("utils.secure_storage.unprotect_token", side_effect=RuntimeError("synthetic failure")):
            self.assertTrue(tray_common.apply_proxy_config(config))
        self.assertEqual(runtime.helper_mode, "tls-pin")
        self.assertEqual(runtime.helper_token, "")


if __name__ == "__main__":
    unittest.main()
