import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from utils import tray_common


class ConfigMigrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app_dir = self.root / "new-app"
        self.legacy_file = self.root / ".tg-proxy" / "config.json"
        self.legacy_file.parent.mkdir(parents=True)
        self.patches = [
            mock.patch.object(tray_common, "APP_DIR", self.app_dir),
            mock.patch.object(tray_common, "CONFIG_FILE", self.app_dir / "config.json"),
            mock.patch.object(Path, "home", return_value=self.root),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temp.cleanup()

    def _write_legacy(self, value):
        self.legacy_file.write_text(json.dumps(value), encoding="utf-8")

    def test_migrates_old_values_and_backs_up_source(self):
        self._write_legacy({
            "host": "127.0.0.2", "port": 1600,
            "secret": "0123456789abcdef0123456789abcdef",
            "dc_ip": ["2:1.2.3.4", "4:5.6.7.8"],
            "buffer_kb": 512, "helper_host": "203.0.113.10",
            "helper_port": 8443, "use_helper": True,
        })
        cfg = tray_common.load_config()
        self.assertEqual(cfg["host"], "127.0.0.2")
        self.assertEqual(cfg["port"], 1600)
        self.assertEqual(cfg["secret"], "0123456789abcdef0123456789abcdef")
        self.assertEqual(cfg["dc_ip"], ["2:1.2.3.4", "4:5.6.7.8"])
        self.assertEqual(cfg["buf_kb"], 512)
        self.assertEqual(cfg["helper_mode"], "legacy")
        self.assertTrue(cfg["helper_enabled"])
        self.assertEqual(cfg["helper_host"], "203.0.113.10")
        self.assertEqual(cfg["helper_port"], 8443)
        self.assertTrue(self.legacy_file.with_name("config.json.pre-upstream.bak").exists())
        self.assertTrue(tray_common.CONFIG_FILE.exists())

    def test_existing_upstream_values_win_while_missing_fields_are_imported(self):
        self.app_dir.mkdir()
        tray_common.CONFIG_FILE.write_text(json.dumps({
            "host": "127.0.0.9", "port": 1900,
            "secret": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }), encoding="utf-8")
        self._write_legacy({
            "host": "127.0.0.2", "port": 1600,
            "secret": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "buffer_kb": 768, "helper_host": "203.0.113.11",
            "helper_port": 8443, "use_helper": True,
        })
        cfg = tray_common.load_config()
        self.assertEqual(cfg["host"], "127.0.0.9")
        self.assertEqual(cfg["port"], 1900)
        self.assertEqual(cfg["secret"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(cfg["buf_kb"], 768)
        self.assertEqual(cfg["helper_mode"], "legacy")
        self.assertTrue(cfg["helper_enabled"])

    def test_damaged_legacy_json_is_backed_up_and_defaults_load(self):
        self.legacy_file.write_text('{broken', encoding="utf-8")
        cfg = tray_common.load_config()
        self.assertEqual(cfg["helper_mode"], "direct")
        self.assertFalse(cfg["helper_enabled"])
        self.assertTrue(self.legacy_file.with_name("config.json.pre-upstream.bak").exists())
        self.assertTrue(tray_common.CONFIG_FILE.exists())

    def test_damaged_new_json_is_backed_up_before_repair(self):
        self.app_dir.mkdir()
        tray_common.CONFIG_FILE.write_text('{broken', encoding="utf-8")
        cfg = tray_common.load_config()
        self.assertEqual(len(cfg["secret"]), 32)
        self.assertTrue(tray_common.CONFIG_FILE.with_name("config.json.corrupt.bak").exists())
        self.assertEqual(tray_common.CONFIG_FILE.read_text(encoding="utf-8").lstrip()[0], "{")

    def test_existing_helper_modes_are_inferred_before_defaults_and_persisted(self):
        self.app_dir.mkdir()
        for mode, enabled in (("tls-pin", True), ("legacy", True), ("direct", False)):
            with self.subTest(mode=mode):
                stored = {
                    "helper_mode": mode, "helper_host": "203.0.113.10",
                    "helper_port": 8443 if mode == "legacy" else 8444,
                    "helper_fingerprint": "a" * 64, "helper_token_dpapi": "synthetic-ciphertext",
                }
                tray_common.CONFIG_FILE.write_text(json.dumps(stored), encoding="utf-8")
                cfg = tray_common.load_config()
                self.assertIs(cfg["helper_enabled"], enabled)
                for key, value in stored.items():
                    self.assertEqual(cfg[key], value)
                persisted = json.loads(tray_common.CONFIG_FILE.read_text(encoding="utf-8"))
                self.assertIs(persisted["helper_enabled"], enabled)
                self.assertEqual(tray_common.load_config(), cfg)

    def test_explicit_disabled_helper_survives_reload_and_legacy_import(self):
        self.app_dir.mkdir()
        stored = {
            "helper_enabled": False, "helper_mode": "tls-pin",
            "helper_host": "203.0.113.20", "helper_port": 8444,
            "helper_fingerprint": "b" * 64, "helper_token_dpapi": "kept-ciphertext",
        }
        tray_common.CONFIG_FILE.write_text(json.dumps(stored), encoding="utf-8")
        self._write_legacy({"use_helper": True, "helper_host": "203.0.113.99", "helper_port": 8443})
        for _ in range(2):
            cfg = tray_common.load_config()
            for key, value in stored.items():
                self.assertEqual(cfg[key], value)
        self.assertIs(cfg["helper_enabled"], False)

    def test_fresh_configuration_starts_with_helper_disabled(self):
        cfg = tray_common.load_config()
        self.assertIs(cfg["helper_enabled"], False)
        self.assertEqual(cfg["helper_mode"], "direct")


if __name__ == "__main__":
    unittest.main()
