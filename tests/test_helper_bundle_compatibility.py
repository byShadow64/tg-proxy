"""Existing immutable bundles retain their exact historical Helper file set."""
import hashlib
import unittest
import zipfile

from release_tools.bundle import BundleError, load_bundle
from tests.test_release_bundle import PreparedBundleMixin


class HelperBundleCompatibilityTest(PreparedBundleMixin, unittest.TestCase):
    def historical_pairing_archive(self):
        helper = self.assets / "TgWsProxy_helper.zip"
        with zipfile.ZipFile(helper, "w") as archive:
            for name in sorted(self.core.HELPER_FILES_1151):
                archive.writestr("TgWsProxy-helper/" + name, self.sources[name])
        checksum = self.assets / "SHA256SUMS.txt"
        checksum.write_text("".join(
            hashlib.sha256((self.assets / name).read_bytes()).hexdigest() + "  " + name + "\n"
            for name in ("TgWsProxy_windows.exe", "TgWsProxy_helper.zip")), encoding="ascii")
        for name in (helper.name, checksum.name):
            self.manifest["assets"][name] = hashlib.sha256((self.assets / name).read_bytes()).hexdigest()
        self.repack_source()

    def remove_pairing_file(self):
        self.sources.pop("helper_pairing.py")
        helper = self.assets / "TgWsProxy_helper.zip"
        with zipfile.ZipFile(helper, "w") as archive:
            for name in sorted(self.core.HELPER_FILES_1151 - {"helper_pairing.py"}):
                archive.writestr("TgWsProxy-helper/" + name, self.sources[name])
        checksum = self.assets / "SHA256SUMS.txt"
        checksum.write_text("".join(
            hashlib.sha256((self.assets / name).read_bytes()).hexdigest() + "  " + name + "\n"
            for name in ("TgWsProxy_windows.exe", "TgWsProxy_helper.zip")), encoding="ascii")
        for name in (helper.name, checksum.name):
            self.manifest["assets"][name] = hashlib.sha256((self.assets / name).read_bytes()).hexdigest()
        self.repack_source()

    def test_historical_1_15_0_bundle_loads_without_modifying_its_bytes(self):
        self.prepare_fixture(version="1.15.0")
        self.remove_pairing_file()
        paths = [self.root / "source.zip", self.root / "manifest.json", *self.assets.iterdir()]
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}
        bundle = load_bundle(self.root)
        self.assertEqual(bundle.version, "1.15.0")
        self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths})

    def test_new_1_15_1_bundle_requires_the_pairing_module(self):
        self.prepare_fixture(version="1.15.1")
        self.remove_pairing_file()
        with self.assertRaises(BundleError) as caught:
            load_bundle(self.root)
        self.assertEqual(caught.exception.code, "helper_archive")

    def test_complete_1_15_1_bundle_with_pairing_module_loads(self):
        self.prepare_fixture(version="1.15.1")
        self.historical_pairing_archive()
        helper = self.assets / "TgWsProxy_helper.zip"
        original = helper.read_bytes()
        bundle = load_bundle(self.root)
        self.assertEqual(bundle.version, "1.15.1")
        self.assertEqual(original, helper.read_bytes())

    def test_new_registry_version_requires_complete_registry_payload(self):
        self.prepare_fixture(version="1.15.2")
        self.historical_pairing_archive()
        with self.assertRaises(BundleError) as caught:
            load_bundle(self.root)
        self.assertEqual("helper_archive", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
