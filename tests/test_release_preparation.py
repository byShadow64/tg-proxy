import hashlib
import importlib.util
from pathlib import Path
import sys
from unittest.mock import patch
from unittest.mock import Mock
from contextlib import redirect_stderr, redirect_stdout
import io
import unittest

from release_tools.bundle import BundleError, load_bundle
from tests.test_release_bundle import PreparedBundleMixin

PATH = Path(__file__).resolve().parents[1] / "packaging/prepare_release.py"
SPEC = importlib.util.spec_from_file_location("test_release_preparer", PATH)
preparer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preparer
SPEC.loader.exec_module(preparer)



class ReleasePreparationTest(PreparedBundleMixin, unittest.TestCase):
    def setUp(self):
        self.prepare_fixture()
        self.checkout = self.folder / "checkout"
        self.checkout.mkdir()
        for name, data in self.sources.items():
            path = self.checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.executable = self.folder / "already-tested.exe"
        self.executable.write_bytes((self.assets / "TgWsProxy_windows.exe").read_bytes())
        self.root_patch = patch.object(preparer, "ROOT", self.checkout)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_preparation_reuses_exact_bytes_and_never_overwrites_different_exe(self):
        output = self.folder / "prepared"
        first = preparer.prepare(self.executable, output)
        hashes = {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in first}
        self.assertEqual(4, len(first))
        preparer.prepare(self.executable, output)
        self.assertEqual(hashes, {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in first})
        self.executable.write_bytes(b"MZ-DIFFERENT-EXE")
        with self.assertRaises(FileExistsError):
            preparer.prepare(self.executable, output)
        self.assertEqual(hashes, {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in first})

    def test_complete_bundle_is_prepared_without_a_builder_or_overwriting(self):
        commands = []
        def git(args, **kwargs):
            commands.append(args)
            if args[1] == "branch":
                return "main\n"
            if args[1] == "status":
                return b""
            if args[1] == "rev-parse":
                return "a" * 40 + "\n"
            if args[1] == "ls-files":
                return "\0".join(self.sources).encode()
            raise AssertionError("No build command is allowed")
        target = self.folder / "new-publication"
        before = self.executable.read_bytes()
        with patch.object(preparer.subprocess, "check_output", side_effect=git), \
                patch("proxy.__version__", self.manifest["version"]):
            preparer.create_bundle(self.executable, target)
        bundle = load_bundle(target)
        self.assertEqual(before, bundle.assets["TgWsProxy_windows.exe"].read_bytes())
        self.assertTrue(all(command[0] == "git" for command in commands))
        with patch.object(preparer.subprocess, "check_output", side_effect=git), \
                patch("proxy.__version__", self.manifest["version"]):
            with self.assertRaises(FileExistsError):
                preparer.create_bundle(self.executable, target)

    def test_new_diagnostics_bundle_is_prepared_as_complete_unsigned_data(self):
        self.prepare_fixture(version="1.15.0")
        self.sources.update({
            "ui/connection_diagnostics.py": b"raise RuntimeError('DO NOT EXECUTE UI SOURCE')\n",
            "utils/connection_diagnostics.py": b"raise RuntimeError('DO NOT EXECUTE BACKEND SOURCE')\n",
        })
        checkout = self.folder / "checkout"
        checkout.mkdir()
        for name, data in self.sources.items():
            file = checkout / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
        executable = self.folder / "tested-1.15.0.exe"
        executable.write_bytes((self.assets / "TgWsProxy_windows.exe").read_bytes())
        commands = []

        def git(args, **kwargs):
            commands.append(args)
            if args[1] == "branch":
                return "codex/prepare-stable-1.15.0\n"
            if args[1] == "status":
                return b""
            if args[1] == "rev-parse":
                return "a" * 40 + "\n"
            if args[1] == "ls-files":
                return "\0".join(self.sources).encode()
            raise AssertionError("Only source inspection is allowed; never build or publish")

        output = self.folder / "unsigned-new-publication"
        with patch.object(preparer, "ROOT", checkout), patch(
                "proxy.__version__", "1.15.0"), patch.object(
                preparer.subprocess, "check_output", side_effect=git):
            preparer.create_bundle(executable, output, build_commit="b" * 40)
        bundle = load_bundle(output)
        self.assertEqual("1.15.0", bundle.version)
        self.assertEqual("b" * 40, bundle.build_commit)
        self.assertEqual(executable.read_bytes(), bundle.assets["TgWsProxy_windows.exe"].read_bytes())
        self.assertEqual(self.sources["docs/RELEASE_NOTES.md"].decode(), bundle.notes)
        self.assertTrue(all(command[0] == "git" for command in commands))
        self.assertFalse((output / "approval.json").exists())
        import zipfile
        with zipfile.ZipFile(bundle.source_zip) as archive:
            self.assertEqual(set(self.sources), set(archive.namelist()))
            for name in ("ui/connection_diagnostics.py", "utils/connection_diagnostics.py"):
                self.assertEqual(self.sources[name], archive.read(name))

    def test_diagnostic_gate_does_not_accept_legacy_prerelease_or_private_checkout(self):
        self.sources["ui/connection_diagnostics.py"] = b"# source must not be omitted\n"

        def git(args, **kwargs):
            return {"branch": "main\n", "status": b"", "rev-parse": "a" * 40 + "\n",
                    "ls-files": "\0".join(self.sources).encode()}[args[1]]

        output = self.folder / "forbidden-diagnostics"
        with patch("proxy.__version__", "1.14.9"), patch.object(
                preparer.subprocess, "check_output", side_effect=git):
            with self.assertRaises(BundleError) as caught:
                preparer.create_bundle(self.executable, output)
        self.assertEqual("private_or_test_source", caught.exception.code)
        self.assertFalse(output.exists())
        for version in ("1.15.0-staging.4", "1.15.0-rc.1", "1.15.0+build.1", "01.15.0", "v1.15.0"):
            with self.subTest(version=version), patch("proxy.__version__", version), patch.object(
                    preparer.subprocess, "check_output") as execute:
                with self.assertRaises(ValueError):
                    preparer.create_bundle(self.executable, output)
                execute.assert_not_called()
        self.sources["private_progress_probe.py"] = b"# always forbidden\n"
        with patch("proxy.__version__", "1.15.0"), patch.object(
                preparer.subprocess, "check_output", side_effect=git):
            with self.assertRaises(BundleError) as caught:
                preparer.create_bundle(self.executable, output)
        self.assertEqual("private_or_test_source", caught.exception.code)
        self.assertFalse(output.exists())

    def test_staging_and_dirty_source_cannot_be_packaged(self):
        with patch.object(preparer.subprocess, "check_output", return_value="Staging\n"):
            with self.assertRaises(ValueError):
                preparer.create_bundle(self.executable, self.folder / "forbidden")
        self.assertFalse((self.folder / "forbidden").exists())
