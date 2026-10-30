"""Stable Windows taskbar identity, independent of Tk's toolkit defaults."""
from __future__ import annotations

import ctypes
import sys


def set_application_identity() -> None:
    if sys.platform != "win32":
        return
    # A fixed identity lets Explorer group our windows by the application,
    # rather than by Python/Tk or a toolkit window created during startup.
    identity = ("byShadow64.TGProxy.Windows" if getattr(sys, "frozen", False)
                else "byShadow64.TGProxy.Development")
    try:
        function = ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID
        function.argtypes = [ctypes.c_wchar_p]
        function.restype = ctypes.c_long
        function(identity)
    except (AttributeError, OSError):
        pass  # Window icons remain usable on systems without this shell API.


def install_native_icons(root, path) -> None:
    """Set both sizes on the real wrapper HWND and retain owned HICONs."""
    if sys.platform != "win32":
        return
    from ctypes import wintypes
    user = ctypes.windll.user32
    user.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user.GetAncestor.restype = wintypes.HWND
    user.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR,
                               wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
    user.LoadImageW.restype = wintypes.HANDLE
    user.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user.SendMessageW.restype = wintypes.LPARAM
    user.DestroyIcon.argtypes = [wintypes.HICON]
    user.DestroyIcon.restype = wintypes.BOOL
    hwnd = user.GetAncestor(root.winfo_id(), 2) or root.winfo_id()  # GA_ROOT
    owned = getattr(root, "_tg_native_icons", None)
    if owned is None:
        owned = []
        for kind, metric in ((0, 49), (1, 11)):  # ICON_SMALL/BIG, SM_CXSMICON/CXICON
            size = user.GetSystemMetrics(metric)
            handle = user.LoadImageW(None, str(path), 1, size, size, 0x10)  # IMAGE_ICON/LR_LOADFROMFILE
            if handle:
                owned.append((kind, handle))
        root._tg_native_icons = owned

        def release(event):
            if event.widget is root:
                for kind, handle in owned:
                    user.SendMessageW(hwnd, 0x80, kind, 0)  # WM_SETICON
                    user.DestroyIcon(handle)
                owned.clear()

        root.bind("<Destroy>", release, add="+")
    for kind, handle in owned:
        user.SendMessageW(hwnd, 0x80, kind, handle)
