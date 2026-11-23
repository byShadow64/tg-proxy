"""Executable authorization is a publisher signature, including install-time refresh."""
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import URLError

from utils import update_check
from tests.signed_update_fixtures import KEYS, signed_release

DIGEST = "sha256:" + hashlib.sha256(b"payload").hexdigest()


class WindowsAuthorizationTest(unittest.TestCase):
    def setUp(self):
        self.keys = patch.object(update_check, "TRUSTED_UPDATE_KEYS", KEYS)
        self.keys.start(); self.addCleanup(self.keys.stop)
        self.asset = {"name": "TgWsProxy_windows.exe", "url": "https://github.com/example/app.exe",
                      "digest": DIGEST, "size": 7, "version": "1.15.5", "current_version": "1.15.4",
                      "source": "github", "manifest_url": "https://backup.invalid/latest.json"}

    def release(self, **kwargs):
        return signed_release(kwargs.pop("version", "1.15.5"), kwargs.pop("digest", DIGEST), **kwargs)

    def test_hash_or_claimed_verified_flag_cannot_offer_a_windows_install(self):
        for extra in ({}, {"verified": True}, {"_signed_manifest": b"untrusted"}):
            with self.subTest(extra=extra), patch.dict(update_check._state, {"assets": [{**self.asset, **extra}]}):
                self.assertIsNone(update_check.find_asset(self.asset["name"]))

    def test_real_signed_discovery_proof_binds_version_name_digest_and_size(self):
        proof = self.release()["assets"][0]["_signed_manifest"]
        signed = {**self.asset, "_signed_manifest": proof}
        self.assertTrue(update_check.has_signed_authorization(signed))
        for changed in ({"version": "1.15.6"}, {"name": "TgWsProxy_helper.zip"},
                        {"digest": "sha256:" + "a" * 64}, {"size": 8}, {"size": True}):
            with self.subTest(changed=changed):
                self.assertFalse(update_check.has_signed_authorization({**signed, **changed}))

    def test_expired_signature_cannot_offer_an_install(self):
        asset = {**self.asset, "_signed_manifest": self.release(expired=True)}
        self.assertFalse(update_check.has_signed_authorization(asset))

    def test_install_refreshes_authorization_before_downloading_even_with_cached_proof(self):
        asset = {**self.asset, "_signed_manifest": self.release()["assets"][0]["_signed_manifest"]}
        with patch.object(update_check, "fetch_backup_release", side_effect=ValueError("signature unavailable")) as fetch, \
                patch.object(update_check, "download_asset") as download:
            with self.assertRaises(ValueError):
                update_check.download_release_asset(asset, Path("unused"), require_signed=True)
        fetch.assert_called_once_with(self.asset["manifest_url"])
        download.assert_not_called()

    def test_fresh_matching_signature_allows_github_download_and_adds_signed_size(self):
        asset = dict(self.asset); asset.pop("size")
        with patch.object(update_check, "fetch_backup_release", return_value=self.release()) as fetch, \
                patch.object(update_check, "download_asset", return_value=Path("verified")) as download:
            path, actual = update_check.download_release_asset(asset, Path("unused"), require_signed=True)
        self.assertEqual(path, Path("verified"))
        self.assertEqual(actual["size"], 7)
        self.assertEqual(download.call_args.kwargs["size"], 7)
        fetch.assert_called_once()

    def test_github_offline_can_download_identical_authorized_backup_bytes(self):
        with patch.object(update_check, "fetch_backup_release", side_effect=[self.release(), self.release()]), \
                patch.object(update_check, "download_asset", side_effect=[URLError("offline"), Path("verified")]) as download:
            _, actual = update_check.download_release_asset(self.asset, Path("unused"), require_signed=True)
        self.assertEqual(actual["source"], "backup")
        self.assertEqual(actual["version"], self.asset["version"])
        self.assertEqual(actual["digest"], self.asset["digest"])
        self.assertEqual(download.call_count, 2)

    def test_pending_github_install_cannot_switch_to_other_version_or_hash(self):
        for changed in (self.release(version="1.15.6"), self.release(digest="sha256:" + "b" * 64)):
            with self.subTest(changed=changed["latest"]), \
                    patch.object(update_check, "fetch_backup_release", side_effect=[self.release(), changed]), \
                    patch.object(update_check, "download_asset", side_effect=URLError("offline")) as download:
                with self.assertRaises(ValueError):
                    update_check.download_release_asset(self.asset, Path("unused"), require_signed=True)
                self.assertEqual(download.call_count, 1)

    def test_unsigned_github_release_remains_discoverable_for_manual_page(self):
        release = {"tag_name": "v1.15.5", "html_url": "https://github.com/example/releases/v1.15.5",
                   "assets": [{"name": self.asset["name"], "browser_download_url": self.asset["url"],
                               "digest": DIGEST, "size": 7}]}
        with patch.object(update_check, "_state", dict(update_check.get_status())), \
                patch.object(update_check, "fetch_latest_release", return_value=release), \
                patch.object(update_check, "fetch_backup_release", side_effect=URLError("offline")):
            update_check.run_check("1.15.4")
            self.assertTrue(update_check.get_status()["has_update"])
            self.assertIsNone(update_check.find_asset(self.asset["name"]))
