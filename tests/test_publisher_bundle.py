"""Prepared-bundle validation is data-only and uses synthetic release files."""
import ast
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import shutil
import unittest
import zipfile
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from publisher.bundle import BundleError, _source_name, export_bundle, load_bundle, revalidate_bundle
from publisher.legacy import publication_core


class PreparedBundleMixin:
    def prepare_fixture(self, *, version="1.14.9"):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name).resolve()
        self.root = self.folder / "publication"
        self.root.mkdir()
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.core = publication_core()
        self.pe = patch.object(self.core, "_windows_version", return_value=tuple(int(part) for part in version.split(".")) + (0,))
        self.pe.start()
        self.addCleanup(self.pe.stop)
        self.sources = {name: b"# Synthetic public source\n" for name in self.core.HELPER_FILES}
        self.sources["proxy/__init__.py"] = ("__version__ = " + repr(version) + "\n").encode("utf-8")
        self.sources["CHANGELOG.md"] = ("# Changes\n\n## " + version + "\n").encode("utf-8")
        self.sources["docs/RELEASE_NOTES.md"] = ("TG Proxy " + version + "\n").encode("utf-8")
        (self.assets / "TgWsProxy_windows.exe").write_bytes(b"MZ-SYNTHETIC-NOT-EXECUTABLE")
        with zipfile.ZipFile(self.assets / "TgWsProxy_helper.zip", "w") as archive:
            for name in sorted(self.core.HELPER_FILES):
                archive.writestr("TgWsProxy-helper/" + name, self.sources[name])
        (self.assets / "CHANGELOG.md").write_bytes(self.sources["CHANGELOG.md"])
        (self.assets / "SHA256SUMS.txt").write_text("".join(
            hashlib.sha256((self.assets / name).read_bytes()).hexdigest() + "  " + name + "\n"
            for name in ("TgWsProxy_windows.exe", "TgWsProxy_helper.zip")), encoding="ascii")
        (self.root / "RELEASE_NOTES.md").write_bytes(self.sources["docs/RELEASE_NOTES.md"])
        self.manifest = {"version": version, "created_at": "2026-10-25T00:00:00Z",
                         "source_commit": "a" * 40, "build_commit": "b" * 40,
                         "release_ready": True, "assets": {
                             name: hashlib.sha256((self.assets / name).read_bytes()).hexdigest()
                             for name in self.core.ASSET_NAMES}}
        self.repack_source()

    def save_manifest(self):
        (self.root / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def repack_source(self):
        with zipfile.ZipFile(self.root / "source.zip", "w") as archive:
            for name, data in self.sources.items():
                archive.writestr(name, data)
        self.manifest["files"] = {name: hashlib.sha256(data).hexdigest() for name, data in self.sources.items()}
        self.manifest["source_zip_sha256"] = hashlib.sha256((self.root / "source.zip").read_bytes()).hexdigest()
        self.save_manifest()

    def error(self, code):
        with self.assertRaises(BundleError) as caught:
            load_bundle(self.root)
        self.assertEqual(code, caught.exception.code)
        self.assertNotIn("SYNTHETIC-PASSWORD", str(caught.exception))


class PublisherBundleTest(PreparedBundleMixin, unittest.TestCase):
    def setUp(self):
        self.prepare_fixture()

    def test_complete_bundle_is_data_only_and_identity_is_stable(self):
        self.sources["proxy/__init__.py"] += b"raise RuntimeError('MUST NEVER EXECUTE SOURCE')\n"
        self.repack_source()
        # Update the allowlisted Helper's matching public source too.
        with zipfile.ZipFile(self.assets / "TgWsProxy_helper.zip", "w") as archive:
            for name in sorted(self.core.HELPER_FILES):
                archive.writestr("TgWsProxy-helper/" + name, self.sources[name])
        helper_hash = hashlib.sha256((self.assets / "TgWsProxy_helper.zip").read_bytes()).hexdigest()
        self.manifest["assets"]["TgWsProxy_helper.zip"] = helper_hash
        text = (self.assets / "SHA256SUMS.txt").read_text()
        text = text.splitlines()[0] + "\n" + helper_hash + "  TgWsProxy_helper.zip\n"
        (self.assets / "SHA256SUMS.txt").write_text(text, encoding="ascii")
        self.manifest["assets"]["SHA256SUMS.txt"] = hashlib.sha256((self.assets / "SHA256SUMS.txt").read_bytes()).hexdigest()
        self.save_manifest()
        first, second = load_bundle(self.root), load_bundle(self.root / "manifest.json")
        self.assertEqual(first.bundle_id, second.bundle_id)
        self.assertEqual("1.14.9", first.version)
        self.assertEqual(4, len(first.assets))

    def test_altered_executable_is_rejected_before_any_publication(self):
        (self.assets / "TgWsProxy_windows.exe").write_bytes(b"tampered")
        self.error("asset_hash")

    def test_original_1_14_9_policy_still_rejects_diagnostics_in_source(self):
        for name in ("ui/connection_diagnostics.py", "utils/connection_diagnostics.py"):
            with self.subTest(name=name):
                self.sources[name] = b"raise RuntimeError('UNAPPROVED OLD DIAGNOSTICS')\n"
                self.repack_source()
                self.error("private_or_test_source")

    def test_staging_private_and_incomplete_manifests_are_rejected(self):
        for field in ("do_not_publish", "PRIVATE_DO_NOT_PUBLISH", "private_fixture", "candidate_only", "staging"):
            with self.subTest(field=field):
                self.manifest[field] = True
                self.save_manifest()
                self.error("not_approved_stable")
                self.manifest.pop(field)
        self.manifest["release_ready"] = False
        self.save_manifest()
        self.error("not_approved_stable")

    def test_prerelease_and_duplicate_json_are_not_accepted(self):
        self.manifest["version"] = "1.15.0-staging.2"
        self.save_manifest()
        self.error("stable_version")
        (self.root / "manifest.json").write_text('{"version":"1.14.9","version":"1.14.9"}', encoding="utf-8")
        self.error("duplicate_json")

    def test_manifest_cannot_smuggle_credentials(self):
        self.manifest["ssh_password"] = "SYNTHETIC-PASSWORD"
        self.save_manifest()
        self.error("manifest_fields")

    def test_unexpected_file_and_secret_source_names_are_rejected(self):
        (self.assets / "credentials.txt").write_text("SYNTHETIC-PASSWORD")
        self.error("asset_allowlist")
        (self.assets / "credentials.txt").unlink()
        self.sources["TgWsProxy_data/config.json"] = b'{"token":"SYNTHETIC-PASSWORD"}'
        self.repack_source()
        self.error("private_or_test_source")

    def test_traversal_duplicate_case_and_symlink_archive_are_rejected(self):
        self.sources["../escape.txt"] = b"no extraction"
        self.repack_source()
        self.error("source_path")
        self.assertFalse((self.folder / "escape.txt").exists())
        self.sources.pop("../escape.txt")
        self.sources["PROXY/__init__.py"] = b"case collision"
        self.repack_source()
        self.error("source_archive")

    def test_notes_and_helper_are_bound_to_exact_source_snapshot(self):
        (self.root / "RELEASE_NOTES.md").write_text("untracked notes")
        self.error("source_asset_mismatch")
        (self.root / "RELEASE_NOTES.md").write_bytes(self.sources["docs/RELEASE_NOTES.md"])
        self.sources["helper_server.py"] = b"# different public helper source\n"
        self.repack_source()
        self.error("helper_source_mismatch")

    def test_revalidation_rejects_manifest_change_after_preview(self):
        loaded = load_bundle(self.root)
        self.manifest["created_at"] = "2026-10-25T01:00:00Z"
        self.save_manifest()
        with self.assertRaises(BundleError) as caught:
            revalidate_bundle(loaded)
        self.assertEqual("bundle_changed", caught.exception.code)

    def test_symlink_assets_are_rejected(self):
        asset = self.assets / "TgWsProxy_windows.exe"
        backup = self.folder / "original.exe"
        asset.rename(backup)
        try:
            asset.symlink_to(backup)
        except OSError:
            self.skipTest("Creating Windows symlinks requires a supported test environment")
        self.error("file_type")

    def test_signed_export_is_exact_deterministic_and_never_overwrites(self):
        from publisher import trust
        key = Ed25519PrivateKey.generate()
        encoded = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        with patch.dict(trust.TRUSTED_APPROVAL_KEYS, {"test": encoded}, clear=True):
            loaded = load_bundle(self.root)
            approval = trust.approve_bundle(loaded, key, "test")
            first = export_bundle(loaded, approval, self.folder / "first.zip")
            second = export_bundle(loaded, approval, self.folder / "second.zip")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(8, len(archive.namelist()))
                for name in ("manifest.json", "source.zip", "RELEASE_NOTES.md"):
                    self.assertEqual((self.root / name).read_bytes(), archive.read(name))
                for name, path in loaded.assets.items():
                    self.assertEqual(path.read_bytes(), archive.read("assets/" + name))
            with self.assertRaises(BundleError):
                export_bundle(loaded, approval, first)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_transport_rejects_bytes_substituted_during_copy(self):
        from publisher import trust
        key = Ed25519PrivateKey.generate()
        encoded = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        with patch.dict(trust.TRUSTED_APPROVAL_KEYS, {"test": encoded}, clear=True):
            loaded = load_bundle(self.root)
            approval = trust.approve_bundle(loaded, key, "test")
            real_copy = shutil.copyfileobj
            changed = False
            def race(source, destination, length):
                nonlocal changed
                if not changed and str(getattr(source, "name", "")).endswith("manifest.json"):
                    changed = True
                    (self.assets / "TgWsProxy_windows.exe").write_bytes(b"MZ-SUBSTITUTED-AFTER-APPROVAL")
                return real_copy(source, destination, length)
            target = self.folder / "must-not-exist.zip"
            with patch("shutil.copyfileobj", side_effect=race):
                with self.assertRaises(BundleError) as caught:
                    export_bundle(loaded, approval, target)
            self.assertEqual("export_content", caught.exception.code)
            self.assertFalse(target.exists())


class PublisherDiagnosticBundleTest(PreparedBundleMixin, unittest.TestCase):
    def setUp(self):
        self.prepare_fixture(version="1.15.0")
        self.sources.update({
            "ui/connection_diagnostics.py": b"raise RuntimeError('DIAGNOSTIC UI SOURCE MUST STAY DATA')\n",
            "utils/connection_diagnostics.py": b"raise RuntimeError('DIAGNOSTIC BACKEND MUST STAY DATA')\n",
        })
        self.repack_source()

    def test_1_15_diagnostics_are_bound_to_complete_data_only_bundle(self):
        first = load_bundle(self.root)
        self.assertEqual("1.15.0", first.version)
        self.assertEqual(set(self.core.ASSET_NAMES), set(first.assets))
        self.assertEqual(self.sources["docs/RELEASE_NOTES.md"].decode(), first.notes)
        self.assertEqual(first.bundle_id, revalidate_bundle(first).bundle_id)
        self.assertFalse((self.root / "approval.json").exists())
        # Versioned paths do not bypass the existing PE/source/Helper/notes gates.
        with patch.object(self.core, "_windows_version", return_value=(1, 14, 9, 0)):
            self.error("pe_version")
        self.sources["helper_server.py"] += b"# changed after helper packaging\n"
        self.repack_source()
        self.error("helper_source_mismatch")

    def test_diagnostic_allowance_requires_canonical_path_and_strict_stable_version(self):
        paths = ("ui/connection_diagnostics.py", "utils/connection_diagnostics.py")
        for version in (None, "1.14.9", "1.15.0-staging.4", "1.15.0-rc.1", "1.15.0+build.1",
                        "v1.15.0", "01.15.0", "1.015.0", "1.15", True, (1, 15, 0)):
            for name in paths:
                with self.subTest(version=version, name=name):
                    with self.assertRaises(BundleError) as caught:
                        _source_name(name, version=version)
                    self.assertEqual("private_or_test_source", caught.exception.code)
        for version in ("1.15.0", "1.15.1", "1.16.0", "2.0.0"):
            for name in paths:
                with self.subTest(version=version, name=name):
                    self.assertEqual(name, _source_name(name, version=version))
        for name in ("UI/connection_diagnostics.py", "ui/Connection_Diagnostics.py",
                     "UTILS/CONNECTION_DIAGNOSTICS.PY"):
            for version in (None, "1.14.9", "1.15.0"):
                with self.subTest(version=version, name=name):
                    with self.assertRaises(BundleError):
                        _source_name(name, version=version)

    def test_windows_path_aliases_cannot_bypass_diagnostic_or_secret_source_rules(self):
        for name in ("ui./connection_diagnostics.py.", "ui/connection_diagnostics.py.",
                     "utils /connection_diagnostics.py", "config.json.", "signing.key.",
                     "ui/connection_diagnostics.py ", "normal.txt "):
            for version in (None, "1.14.9", "1.15.0"):
                with self.subTest(name=name, version=version):
                    with self.assertRaises(BundleError) as caught:
                        _source_name(name, version=version)
                    self.assertEqual("source_path", caught.exception.code)

    def test_new_version_does_not_allow_private_sources_or_staging_flags(self):
        for name in ("private_progress_probe.py", "PRIVATE_PROGRESS_PROBE.PY", "PRIVATE_DO_NOT_PUBLISH.json",
                     "private-update-client/observer.py", "TgWsProxy_data/config.json", "signing.key", "custom.DPAPI.JSON"):
            with self.subTest(name=name):
                with self.assertRaises(BundleError) as caught:
                    _source_name(name, version="1.15.0")
                self.assertEqual("private_or_test_source", caught.exception.code)
        for name in ("staging", "private_fixture", "PRIVATE_DO_NOT_PUBLISH", "do_not_publish", "candidate_only"):
            with self.subTest(flag=name):
                self.manifest[name] = True
                self.save_manifest()
                self.error("not_approved_stable")
                self.manifest.pop(name)
        self.manifest["version"] = "1.15.0-staging.4"
        self.save_manifest()
        self.error("stable_version")

    def test_new_unsigned_bundle_still_requires_approval_before_any_publisher_mutation(self):
        from publisher import github, trust
        bundle = load_bundle(self.root)
        output = self.folder / "must-not-be-created.zip"
        with patch.object(trust, "approval_file", return_value=self.folder / "missing-approval.json"):
            with self.assertRaises(trust.TrustError) as caught:
                trust.verify_approval(bundle)
            self.assertEqual("approval_required", caught.exception.code)
            with self.assertRaises(trust.TrustError):
                export_bundle(bundle, None, output)
            with patch.object(github, "GitHubClient") as client:
                with self.assertRaises(github.GitHubError) as caught:
                    github.preflight_github(bundle, "owner/repository", "SYNTHETIC-NOT-A-TOKEN")
                self.assertEqual("approval_required", caught.exception.code)
                client.assert_not_called()
        self.assertFalse(output.exists())
        self.assertFalse((self.root / "approval.json").exists())

    def test_publisher_version_resource_is_independent_and_matches_1_0_4(self):
        from publisher import __version__
        self.assertEqual("1.0.4", __version__)
        resource = Path(__file__).resolve().parents[1] / "packaging/publisher_version_info.txt"
        tree = ast.parse(resource.read_text(encoding="utf-8"))
        fixed = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id == "FixedFileInfo")
        versions = {item.arg: ast.literal_eval(item.value) for item in fixed.keywords
                    if item.arg in {"filevers", "prodvers"}}
        self.assertEqual({"filevers": (1, 0, 4, 0), "prodvers": (1, 0, 4, 0)}, versions)
        strings = {ast.literal_eval(node.args[0]): ast.literal_eval(node.args[1])
                   for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == "StringStruct"}
        self.assertEqual("1.0.4.0", strings["FileVersion"])
        self.assertEqual("1.0.4.0", strings["ProductVersion"])
