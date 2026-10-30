# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import os
import customtkinter
from PyInstaller.utils.hooks import collect_data_files, copy_metadata

root = Path(SPEC).resolve().parents[1]
datas = [
    (str(root / "packaging/publish_updates.py"), "packaging"),
    (str(root / "icon.ico"), "."),
    (str(root / "ui/assets/byshadow64.png"), "ui/assets"),
    (os.path.join(os.path.dirname(customtkinter.__file__), "assets"), "customtkinter/assets"),
] + collect_data_files("certifi") + copy_metadata("paramiko")

a = Analysis([str(root / "publisher_main.py")], pathex=[str(root)], binaries=[], datas=datas,
             hiddenimports=["pefile", "publisher.trust", "publisher.github", "publisher.server",
                            "PIL.ImageTk", "PIL._imagingtk", "PIL._tkinter_finder"],
             hookspath=[], hooksconfig={}, runtime_hooks=[],
             excludes=["PIL._avif", "PIL._webp"], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="TGProxyPublisher",
          debug=False, strip=False, upx=False, console=False,
          disable_windowed_traceback=True,
          icon=str(root / "icon.ico"), version=str(root / "packaging/publisher_version_info.txt"))
