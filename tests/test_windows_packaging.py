"""Check the Windows bundle contract without building or launching an EXE."""
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch


class WindowsPackagingTest(unittest.TestCase):
    def setUp(self):
        project = Path(__file__).resolve().parents[1]
        hooks = ModuleType("PyInstaller.utils.hooks")
        hooks.collect_data_files = Mock(return_value=[])
        hooks.copy_metadata = Mock(return_value=[("paramiko.dist-info", "paramiko.dist-info")])
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        customtkinter = ModuleType("customtkinter")
        customtkinter.__file__ = str(project / "test-ctk" / "__init__.py")
        native_tk_bridge = (
            "PIL\\_imagingtk.cp311-win_amd64.pyd", "pillow-tk-bridge.pyd", "EXTENSION")
        analysis = SimpleNamespace(
            pure=[], zipped_data=[], scripts=[], zipfiles=[], datas=[],
            binaries=[native_tk_bridge,
                      ("_tkinter.pyd", "tkinter.pyd", "EXTENSION"),
                      ("PIL\\_imaging.cp311-win_amd64.pyd", "pillow-core.pyd", "EXTENSION"),
                      ("PIL\\_avif.cp311-win_amd64.pyd", "optional-avif.pyd", "EXTENSION")],
        )
        self.native_tk_bridge = native_tk_bridge
        self.analyze = Mock(return_value=analysis)
        self.bundle = Mock()
        # Execute the real spec's filtering logic with an analyzed native module
        # list. PyInstaller is an optional build dependency of the project.
        modules = {
            "PyInstaller": ModuleType("PyInstaller"),
            "PyInstaller.utils": ModuleType("PyInstaller.utils"),
            "PyInstaller.utils.hooks": hooks,
            "customtkinter": customtkinter,
        }
        with patch.dict(sys.modules, modules):
            runpy.run_path(str(project / "packaging" / "windows.spec"), init_globals={
                "SPEC": str(project / "packaging" / "windows.spec"),
                "workpath": self.work.name,
                "Analysis": self.analyze, "PYZ": Mock(), "EXE": self.bundle,
            })

    def test_pillow_tk_bridge_is_explicitly_collected_and_never_excluded(self):
        options = self.analyze.call_args.kwargs
        for module in ("PIL.ImageTk", "PIL._imagingtk", "PIL._tkinter_finder"):
            with self.subTest(module=module):
                self.assertIn(module, options["hiddenimports"])
                self.assertNotIn(module, options["excludes"])

    def test_pillow_tk_bridge_reaches_the_final_onefile_bundle(self):
        binaries = self.bundle.call_args.args[2]
        self.assertIn(self.native_tk_bridge, binaries)
        self.assertTrue(any(name == "_tkinter.pyd" for name, _, _ in binaries))

    def test_helper_sources_and_paramiko_license_metadata_are_bundled(self):
        options = self.analyze.call_args.kwargs
        self.assertIn("paramiko", options["hiddenimports"])
        self.assertIn(("paramiko.dist-info", "paramiko.dist-info"), options["datas"])
        payload = Path(self.work.name) / "helper_payload.tar"
        self.assertTrue(payload.is_file())
        self.assertIn((str(payload), "."), options["datas"])

    def test_author_sidebar_badge_is_bundled(self):
        project = Path(__file__).resolve().parents[1]
        asset = project / "ui" / "assets" / "byshadow64.png"
        self.assertTrue(asset.is_file())
        self.assertIn((str(asset), "ui/assets"), self.analyze.call_args.kwargs["datas"])

    def test_translation_resources_exclude_local_caches_and_untracked_files(self):
        translations = [Path(source) for source, target in
                        self.analyze.call_args.kwargs["datas"] if target == "ui/i18n"]
        self.assertEqual({path.name for path in translations},
                         {"__init__.py", "ru.json", "en.json"})
        self.assertTrue(all(path.is_file() for path in translations))


if __name__ == "__main__":
    unittest.main()
