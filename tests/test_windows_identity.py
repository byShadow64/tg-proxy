"""Real HWND checks after CustomTkinter's delayed icon replacement."""
import subprocess
import sys
import unittest


@unittest.skipUnless(sys.platform == "win32", "Windows shell integration")
class WindowsIdentityTest(unittest.TestCase):
    def test_real_wrapper_keeps_both_icons_after_delay_and_reopen(self):
        code = r'''
import ctypes
from ctypes import wintypes
import customtkinter as ctk
from utils.windows_identity import set_application_identity
from ui.ctk_theme import install_window_icon
set_application_identity()
value=ctypes.c_wchar_p()
get_identity=ctypes.windll.shell32.GetCurrentProcessExplicitAppUserModelID
get_identity.argtypes=[ctypes.POINTER(ctypes.c_wchar_p)]
get_identity.restype=ctypes.c_long
assert get_identity(ctypes.byref(value))==0
assert value.value=="byShadow64.TGProxy.Development"
ctypes.windll.ole32.CoTaskMemFree.argtypes=[ctypes.c_void_p]
ctypes.windll.ole32.CoTaskMemFree(ctypes.cast(value,ctypes.c_void_p))
root=ctk.CTk()
root.withdraw()
install_window_icon(root, default=True)
window=ctk.CTkToplevel(root)
window.geometry("240x160+12000+12000")
install_window_icon(window)
def check():
    user=ctypes.windll.user32
    hwnd=user.GetAncestor(window.winfo_id(),2)
    assert len(window._tg_native_icons)==2
    for kind,handle in window._tg_native_icons:
        assert user.SendMessageW(hwnd,0x7F,kind,0)==handle
    window.withdraw()
    window.deiconify()
    root.after(400, check_again)
def check_again():
    user=ctypes.windll.user32
    hwnd=user.GetAncestor(window.winfo_id(),2)
    for kind,handle in window._tg_native_icons:
        assert user.SendMessageW(hwnd,0x7F,kind,0)==handle
    window.destroy()
    assert window._tg_native_icons==[]
    root.destroy()
errors=[]
root.report_callback_exception=lambda *args: (errors.append(args),root.destroy())
root.after(800,check)
root.after(4000,root.destroy)
root.mainloop()
assert not errors,errors
print("WINDOW_ICONS_OK")
'''
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WINDOW_ICONS_OK", result.stdout)
