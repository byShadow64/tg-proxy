"""Small Windows DPAPI wrapper for user-scoped secrets."""
from __future__ import annotations

import base64
import ctypes
import os
from ctypes import wintypes


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(value: bytes):
    buffer = ctypes.create_string_buffer(value)
    return _DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def _dpapi(protect: bool, value: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("Windows DPAPI is only available on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    blob_ptr = ctypes.POINTER(_DataBlob)
    crypt32.CryptProtectData.argtypes = [
        blob_ptr, wintypes.LPCWSTR, blob_ptr, wintypes.LPVOID,
        wintypes.LPVOID, wintypes.DWORD, blob_ptr,
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        blob_ptr, ctypes.POINTER(wintypes.LPWSTR), blob_ptr, wintypes.LPVOID,
        wintypes.LPVOID, wintypes.DWORD, blob_ptr,
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    source, source_buffer = _blob(value)
    target = _DataBlob()
    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(source), "TG WS Proxy helper token", None, None, None,
            0x1, ctypes.byref(target),
        )
    else:
        description = wintypes.LPWSTR()
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(source), ctypes.byref(description), None, None, None,
            0x1, ctypes.byref(target),
        )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)
        if not protect and description:
            kernel32.LocalFree(description)
        # Keep the input allocation alive until the DPAPI call has returned.
        del source_buffer


def protect_token(token: str) -> str:
    if not token:
        return ""
    return base64.b64encode(_dpapi(True, token.encode("utf-8"))).decode("ascii")


def unprotect_token(value: str) -> str:
    if not value:
        return ""
    try:
        ciphertext = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("Stored helper token is malformed") from exc
    return _dpapi(False, ciphertext).decode("utf-8")
