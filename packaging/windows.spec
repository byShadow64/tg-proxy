# -*- mode: python ; coding: utf-8 -*-

import sys
import os
import importlib.util
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, copy_metadata

block_cipher = None

# customtkinter ships JSON themes + assets that must be bundled
import customtkinter
ctk_path = os.path.dirname(customtkinter.__file__)
certifi_datas = collect_data_files('certifi')
paramiko_datas = copy_metadata('paramiko')

_project_root = Path(SPEC).resolve().parents[1]
_payload_spec = importlib.util.spec_from_file_location(
    'tg_helper_payload_builder', _project_root / 'utils' / 'helper_payload.py')
_payload_builder = importlib.util.module_from_spec(_payload_spec)
_payload_spec.loader.exec_module(_payload_builder)
_payload_path = Path(workpath) / 'helper_payload.tar'
_payload_path.parent.mkdir(parents=True, exist_ok=True)
_payload_path.write_bytes(_payload_builder.build_helper_payload(_project_root))

_i18n_path = os.path.join(os.path.dirname(SPEC), os.pardir, 'ui', 'i18n')

a = Analysis(
    [os.path.join(os.path.dirname(SPEC), os.pardir, 'windows.py')],
    pathex=[],
    binaries=[],
    datas=[(os.path.join(ctk_path, 'assets'), 'customtkinter/assets'),
           (str(_payload_path), '.'),
           (str(_project_root / 'ui' / 'assets' / 'byshadow64.png'), 'ui/assets')]
          + [(os.path.join(_i18n_path, name), 'ui/i18n')
             for name in ('__init__.py', 'ru.json', 'en.json')]
          + certifi_datas + paramiko_datas,
    hiddenimports=[
        'httpx',
        'h2',
        'paramiko',
        'pystray._win32',
        # CTkImage and the traffic chart use Pillow's native Tk photo bridge.
        'PIL.ImageTk',
        'PIL._imagingtk',
        'PIL._tkinter_finder',
        'customtkinter',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.ciphers.algorithms',
        'cryptography.hazmat.primitives.ciphers.modes',
        'cryptography.hazmat.backends.openssl',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'PIL._avif',
        'PIL._webp',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

_PIL_EXCLUDE_PYDS = {
    '_avif', '_webp',
    'FpxImagePlugin', 'MicImagePlugin',
}
a.binaries = [
    (name, path, typ)
    for name, path, typ in a.binaries
    if not any(ex in name for ex in _PIL_EXCLUDE_PYDS)
]

icon_path = os.path.join(os.path.dirname(SPEC), os.pardir, 'icon.ico')
version_path = os.path.join(os.path.dirname(SPEC), 'version_info.txt')
if os.path.exists(icon_path):
    a.datas += [('icon.ico', icon_path, 'DATA')]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='TgWsProxy',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path if os.path.exists(icon_path) else None,
    version=version_path if os.path.exists(version_path) else None,
)
