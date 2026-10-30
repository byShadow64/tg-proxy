"""Windows entry point for the separate, semi-automatic release publisher."""
from __future__ import annotations

import argparse
import logging
import sys


ACTIVATION_NAME = r"Local\TGProxyPublisher.Activate.v1"
MUTEX_NAME = r"Local\TGProxyPublisher.Instance.v1"


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Неверные параметры издателя. Токен задаётся только в окне программы.\n")


def _instance():
    if sys.platform != "win32":
        return None, None, True
    import ctypes
    from ctypes import wintypes
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    api.CreateMutexW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    ctypes.set_last_error(0)
    handle = api.CreateMutexW(None, False, MUTEX_NAME)
    error = ctypes.get_last_error()
    if not handle:
        raise RuntimeError("publisher_instance")
    return api, handle, error != 183


def main(argv=None):
    parser = _Parser(description="TG Proxy Publisher: publish a verified package without rebuilding it")
    parser.add_argument("--bundle", help="Prepared publication folder to inspect")
    parser.add_argument("--keys", help="Existing publisher DPAPI key file belonging to this Windows user")
    parser.add_argument("--appearance", choices=("dark", "light"), default="dark")
    args = parser.parse_args(argv)
    api = handle = activation = None
    try:
        api, handle, primary = _instance()
        from utils.windows_activation import InstanceActivation, request_activation
        if not primary:
            request_activation(ACTIVATION_NAME)
            return 0
        if sys.platform == "win32":
            activation = InstanceActivation(ACTIVATION_NAME)
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("byShadow64.TGProxyPublisher")
        # Library logs must not bypass the publisher's code-only journal.
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        from publisher.app import PublisherApp
        app = PublisherApp(bundle_path=args.bundle, keys_path=args.keys, appearance=args.appearance)
        if activation:
            activation.start(app.activation_requested.set)
        app.mainloop()
        return 0
    except Exception:
        # A windowed build must never show raw exception/HTTP data containing
        # tokens, key paths, headers or remote replies in its failure dialog.
        try:
            from tkinter import messagebox
            messagebox.showerror("TG Proxy Publisher", "Издатель не удалось запустить. Проверьте настройки и целостность программы. Код: publisher_startup")
        except Exception:
            pass
        return 1
    finally:
        if activation:
            activation.close()
        if api is not None and handle:
            api.CloseHandle(handle)


if __name__ == "__main__":
    raise SystemExit(main())
