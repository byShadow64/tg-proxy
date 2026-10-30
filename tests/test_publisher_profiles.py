import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from publisher.profiles import (ProfileError, ProfileStore, ServerCredentials, ServerProfile,
                               default_keys_path, load_default_profile, validate_profile)


class PublisherProfilesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name).resolve()
        self.store = ProfileStore(self.folder / "profiles.json")
        self.profile = ServerProfile(host_key="SHA256:" + "a" * 43)

    def test_optional_secrets_are_separate_dpapi_ciphertext(self):
        secret = "SYNTHETIC-PASSWORD-DO-NOT-LOG"
        def protect(text):
            return base64.b64encode(text.encode()[::-1]).decode()
        def unprotect(cipher):
            return base64.b64decode(cipher)[::-1].decode()
        private = {"github_token": secret, "servers": {"default": {"password": secret}}}
        with patch("publisher.profiles.protect_token", side_effect=protect), patch(
                "publisher.profiles.unprotect_token", side_effect=unprotect):
            self.store.save([self.profile], private)
            raw = self.store.path.read_text(encoding="utf-8")
            self.assertNotIn(secret, raw)
            self.assertNotIn(secret, repr(ServerCredentials(password=secret)))
            profiles, loaded, active = self.store.load()
            self.assertEqual(private, loaded)
            self.assertEqual("default", active)
            self.assertEqual(self.profile, profiles[0])
            self.store.save(profiles, None)
            self.assertEqual(private, self.store.load()[1])
            self.store.save(profiles, {})
            self.assertEqual({}, self.store.load()[1])

    @unittest.skipUnless(os.name == "nt", "Actual DPAPI is Windows-only")
    def test_real_windows_dpapi_profile_roundtrip(self):
        secret = "SYNTHETIC-REAL-DPAPI-TEST-NOT-A-CREDENTIAL"
        private = {"github_token": secret, "servers": {"default": {"password": secret}}}
        self.store.save([self.profile], private)
        self.assertNotIn(secret, self.store.path.read_text(encoding="utf-8"))
        self.assertEqual(private, self.store.load()[1])

    def test_dpapi_failure_never_falls_back_to_plaintext(self):
        with patch("publisher.profiles.protect_token", side_effect=RuntimeError("SECRET")):
            with self.assertRaises(ProfileError) as caught:
                self.store.save([self.profile], {"github_token": "SECRET"})
        self.assertEqual("secret_store", caught.exception.code)
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertFalse(self.store.path.exists())

    def test_default_without_legacy_file_is_editable_and_unconfigured(self):
        value = load_default_profile(self.folder / "missing.json")
        self.assertEqual("", value.host_key)
        self.assertEqual("217.177.34.28", value.host)
        self.assertEqual("https://217.177.34.28", value.base_url)

    def test_two_named_servers_do_not_change_client_channel(self):
        from proxy.update_channel import UPDATE_MANIFEST_URL
        before = UPDATE_MANIFEST_URL
        second = replace(self.profile, profile_id="backup", name="Other server", host="other.example.invalid",
                         base_url="https://other.example.invalid/releases", webroot="/release-data")
        self.store.save([self.profile, second], {}, active_id="backup")
        profiles, _, active = self.store.load()
        self.assertEqual("backup", active)
        self.assertEqual(second, profiles[1])
        from proxy.update_channel import UPDATE_MANIFEST_URL as after
        self.assertEqual(before, after)

    def test_invalid_urls_pin_or_paths_are_rejected(self):
        for changes in ({"base_url": "http://insecure.invalid"}, {"base_url": "https://user:secret@example.invalid"},
                        {"webroot": "/"}, {"webroot": "/updates/../etc"}, {"port": True},
                        {"host_key": ""}, {"host": "server\npassword"}):
            with self.subTest(changes=changes):
                with self.assertRaises(ProfileError):
                    validate_profile(replace(self.profile, **changes))

    def test_existing_legacy_settings_are_not_rewritten(self):
        from utils.ssh_setup import _fingerprint
        data = b"synthetic-public-ssh-key"
        path = self.folder / "publisher.dpapi.json"
        original = json.dumps({"host": "server.example.invalid", "host_key": base64.b64encode(data).decode(),
                               "ssh_key_dpapi": "opaque-existing-cipher", "signing_key_dpapi": "opaque-signing"}).encode()
        path.write_bytes(original)
        loaded = load_default_profile(path)
        self.assertEqual(_fingerprint(data), loaded.host_key)
        self.assertEqual(original, path.read_bytes())

    def test_normal_default_has_priority_over_fixed_codex_cache(self):
        home = self.folder / "user"
        local = home / "AppData/Local"
        normal = local / "TGProxyPublisher/publisher.dpapi.json"
        cache = local / "Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Local/TGProxyPublisher/publisher.dpapi.json"
        for path in (normal, cache):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"{}")
        with patch.dict(os.environ, {"USERPROFILE": str(home), "LOCALAPPDATA": str(local)}):
            self.assertEqual(normal.resolve(), default_keys_path().resolve())
            normal.unlink()
            self.assertEqual(cache.resolve(), default_keys_path())
            self.assertEqual(str(cache.resolve()), ServerCredentials().legacy_key_path)
        self.assertEqual(b"{}", cache.read_bytes())

    def test_other_user_and_inherited_localappdata_are_not_searched(self):
        home = self.folder / "isolated-user"
        foreign = self.folder / "foreign-user/AppData/Local"
        other = foreign / "TGProxyPublisher/publisher.dpapi.json"
        other.parent.mkdir(parents=True)
        other.write_bytes(b"FOREIGN-SYNTHETIC-KEYS-NOT-TO-READ")
        with patch.dict(os.environ, {"USERPROFILE": str(home), "LOCALAPPDATA": str(foreign)}):
            chosen = default_keys_path()
            self.assertTrue(chosen.is_relative_to(home))
            self.assertNotEqual(other, chosen)
            self.assertEqual("", load_default_profile().host_key)

    def test_missing_normal_and_cache_leave_healthy_unconfigured_defaults(self):
        home = self.folder / "clean-user"
        with patch.dict(os.environ, {"USERPROFILE": str(home), "LOCALAPPDATA": str(home / "AppData/Local")}):
            value = load_default_profile()
            self.assertEqual("", value.host_key)
            self.assertEqual("legacy", value.auth_method)
            self.assertFalse(default_keys_path().exists())
