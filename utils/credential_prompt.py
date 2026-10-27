"""
Windows-native "prove it's you" prompt (password OR Windows Hello PIN).

Shows the standard Windows Security dialog (CredUIPromptForWindowsCredentialsW - the
same dialog used for RDP / network-share logins) and then VALIDATES what the user
entered with the operating system itself, so nothing is compared or stored by this app:

  1. Primary path - LsaLogonUser with the opaque authentication buffer the dialog
     returns. Because the buffer is handed straight back to the OS's own
     authentication package, this works for passwords, PINs, and other
     Windows Hello credentials alike.
  2. Fallback path - CredUnPackAuthenticationBufferW + LogonUserW. Password only;
     used only if the LSA call is refused by the system (e.g. a policy/privilege error).

Safety properties:
  * The dialog is restricted to the CURRENT user's credential tile
    (CREDUIWIN_ENUMERATE_CURRENT_USER) and, as defence in depth, the logon token that
    comes back must belong to the same SID as this process.
  * The credential buffer is zeroed and freed as soon as it has been checked.
  * Three attempts per request, then a short cool-down before another prompt can open.
  * Only one prompt can be open at a time.
  * If the prompt cannot be shown (non-Windows, API failure) the result is a DENIAL,
    never a silent pass.
"""

from __future__ import annotations

import ctypes
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)

IS_WINDOWS = sys.platform == "win32"

# Outcomes
OK = "ok"
CANCELLED = "cancelled"
FAILED = "failed"            # wrong password/PIN (after all attempts)
BUSY = "busy"                # another prompt is already open / cool-down active
UNAVAILABLE = "unavailable"  # cannot show a native prompt on this system
ERROR = "error"

_MAX_ATTEMPTS = 3
_COOLDOWN_SECONDS = 5.0

_CREDUIWIN_ENUMERATE_CURRENT_USER = 0x200
_ERROR_CANCELLED = 1223
_ERROR_LOGON_FAILURE = 1326
_LOGON32_LOGON_INTERACTIVE = 2
_LOGON32_PROVIDER_DEFAULT = 0
_SECURITY_LOGON_INTERACTIVE = 2
# NTSTATUS values that mean "the LSA route is not usable here", not "wrong password".
_LSA_NOT_USABLE = {0xC0000022, 0xC0000061, 0xC000000D, 0xC00000BB}  # ACCESS_DENIED, PRIVILEGE_NOT_HELD, INVALID_PARAMETER, NOT_SUPPORTED

_prompt_lock = threading.Lock()
_last_failure_at = 0.0


@dataclass
class AuthResult:
    verified: bool
    outcome: str
    message: str = ""


if IS_WINDOWS:
    from ctypes import wintypes as wt

    class CREDUI_INFOW(ctypes.Structure):
        _fields_ = [("cbSize", wt.DWORD), ("hwndParent", wt.HWND), ("pszMessageText", wt.LPCWSTR),
                    ("pszCaptionText", wt.LPCWSTR), ("hbmBanner", wt.HBITMAP)]

    class LSA_STRING(ctypes.Structure):
        _fields_ = [("Length", wt.USHORT), ("MaximumLength", wt.USHORT), ("Buffer", ctypes.c_char_p)]

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

    class TOKEN_SOURCE(ctypes.Structure):
        _fields_ = [("SourceName", ctypes.c_char * 8), ("SourceIdentifier", LUID)]

    class QUOTA_LIMITS(ctypes.Structure):
        _fields_ = [("PagedPoolLimit", ctypes.c_size_t), ("NonPagedPoolLimit", ctypes.c_size_t),
                    ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("PagefileLimit", ctypes.c_size_t), ("TimeLimit", ctypes.c_int64)]

    _credui = ctypes.WinDLL("credui", use_last_error=True)
    _secur32 = ctypes.WinDLL("secur32")
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ole32 = ctypes.WinDLL("ole32")
    _user32 = ctypes.WinDLL("user32")

    _credui.CredUIPromptForWindowsCredentialsW.argtypes = [
        ctypes.POINTER(CREDUI_INFOW), wt.DWORD, ctypes.POINTER(wt.ULONG), ctypes.c_void_p, wt.ULONG,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wt.ULONG), ctypes.POINTER(wt.BOOL), wt.DWORD]
    _credui.CredUIPromptForWindowsCredentialsW.restype = wt.DWORD
    _credui.CredUnPackAuthenticationBufferW.argtypes = [
        wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD),
        wt.LPWSTR, ctypes.POINTER(wt.DWORD), wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
    _credui.CredUnPackAuthenticationBufferW.restype = wt.BOOL

    _secur32.LsaConnectUntrusted.argtypes = [ctypes.POINTER(wt.HANDLE)]
    _secur32.LsaConnectUntrusted.restype = wt.LONG
    _secur32.LsaDeregisterLogonProcess.argtypes = [wt.HANDLE]
    _secur32.LsaDeregisterLogonProcess.restype = wt.LONG
    _secur32.LsaFreeReturnBuffer.argtypes = [ctypes.c_void_p]
    _secur32.LsaFreeReturnBuffer.restype = wt.LONG
    _secur32.LsaLogonUser.argtypes = [
        wt.HANDLE, ctypes.POINTER(LSA_STRING), wt.ULONG, wt.ULONG, ctypes.c_void_p, wt.ULONG,
        ctypes.c_void_p, ctypes.POINTER(TOKEN_SOURCE), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wt.ULONG), ctypes.POINTER(LUID), ctypes.POINTER(wt.HANDLE),
        ctypes.POINTER(QUOTA_LIMITS), ctypes.POINTER(wt.LONG)]
    _secur32.LsaLogonUser.restype = wt.LONG

    _advapi32.AllocateLocallyUniqueId.argtypes = [ctypes.POINTER(LUID)]
    _advapi32.LogonUserW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, wt.DWORD,
                                     ctypes.POINTER(wt.HANDLE)]
    _advapi32.LogonUserW.restype = wt.BOOL
    _advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    _advapi32.OpenProcessToken.restype = wt.BOOL
    _advapi32.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD,
                                              ctypes.POINTER(wt.DWORD)]
    _advapi32.GetTokenInformation.restype = wt.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.LPWSTR)]
    _advapi32.ConvertSidToStringSidW.restype = wt.BOOL
    _kernel32.CloseHandle.argtypes = [wt.HANDLE]
    _kernel32.GetCurrentProcess.restype = wt.HANDLE
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    _user32.FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
    _user32.FindWindowW.restype = wt.HWND


class _Credential:
    """The opaque buffer returned by the dialog. Always wipe() it, even on errors."""

    def __init__(self, pointer: int, size: int, package: int) -> None:
        self.pointer, self.size, self.package = pointer, size, package

    def wipe(self) -> None:
        if self.pointer:
            ctypes.memset(self.pointer, 0, self.size)
            _ole32.CoTaskMemFree(ctypes.c_void_p(self.pointer))
            self.pointer = 0


def _show_prompt(title: str, message: str, parent_title: Optional[str],
                 auth_error: int) -> Optional[_Credential]:
    """Show the Windows Security dialog. Returns None if the user cancelled."""
    hwnd = _user32.FindWindowW(None, parent_title) if parent_title else None
    info = CREDUI_INFOW(ctypes.sizeof(CREDUI_INFOW), hwnd, message[:1000], title[:120], None)
    package, out_ptr = wt.ULONG(0), ctypes.c_void_p()
    out_size, save = wt.ULONG(0), wt.BOOL(False)
    rc = _credui.CredUIPromptForWindowsCredentialsW(
        ctypes.byref(info), auth_error, ctypes.byref(package), None, 0,
        ctypes.byref(out_ptr), ctypes.byref(out_size), ctypes.byref(save),
        _CREDUIWIN_ENUMERATE_CURRENT_USER)
    if rc == _ERROR_CANCELLED:
        return None
    if rc != 0:
        raise OSError(f"CredUIPromptForWindowsCredentials failed with error {rc}")
    return _Credential(out_ptr.value, out_size.value, package.value)


def _token_sid(token: int) -> str:
    size = wt.DWORD(0)
    _advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))   # 1 = TokenUser
    buf = ctypes.create_string_buffer(size.value)
    if not _advapi32.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
        raise OSError("GetTokenInformation failed")
    sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]          # TOKEN_USER.User.Sid
    text = wt.LPWSTR()
    if not _advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(text)):
        raise OSError("ConvertSidToStringSidW failed")
    try:
        return text.value
    finally:
        _kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _current_user_sid() -> str:
    token = wt.HANDLE()
    if not _advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), 0x8, ctypes.byref(token)):  # TOKEN_QUERY
        raise OSError("OpenProcessToken failed")
    try:
        return _token_sid(token)
    finally:
        _kernel32.CloseHandle(token)


def _token_is_current_user(token: int) -> bool:
    try:
        return _token_sid(token) == _current_user_sid()
    except OSError:
        logger.exception("Could not compare account SIDs")
        return False


def _validate_with_lsa(cred: _Credential) -> Optional[bool]:
    """True/False = verdict from the OS. None = LSA route unusable, try the fallback."""
    lsa = wt.HANDLE()
    status = _secur32.LsaConnectUntrusted(ctypes.byref(lsa)) & 0xFFFFFFFF
    if status != 0:
        return None
    try:
        origin_text = b"USBThreatAnalyzer"
        origin = LSA_STRING(len(origin_text), len(origin_text) + 1, origin_text)
        source = TOKEN_SOURCE()
        source.SourceName = b"USBTA"
        _advapi32.AllocateLocallyUniqueId(ctypes.byref(source.SourceIdentifier))
        profile, profile_len = ctypes.c_void_p(), wt.ULONG(0)
        logon_id, token = LUID(), wt.HANDLE()
        quotas, substatus = QUOTA_LIMITS(), wt.LONG(0)
        status = _secur32.LsaLogonUser(
            lsa, ctypes.byref(origin), _SECURITY_LOGON_INTERACTIVE, cred.package,
            ctypes.c_void_p(cred.pointer), cred.size, None, ctypes.byref(source),
            ctypes.byref(profile), ctypes.byref(profile_len), ctypes.byref(logon_id),
            ctypes.byref(token), ctypes.byref(quotas), ctypes.byref(substatus)) & 0xFFFFFFFF
        if status != 0:
            return None if status in _LSA_NOT_USABLE else False
        try:
            return _token_is_current_user(token)
        finally:
            _kernel32.CloseHandle(token)
            if profile:
                _secur32.LsaFreeReturnBuffer(profile)
    finally:
        _secur32.LsaDeregisterLogonProcess(lsa)


def _validate_with_logonuser(cred: _Credential) -> bool:
    """Password-only fallback (cannot validate a PIN)."""
    user, domain, pwd = (ctypes.create_unicode_buffer(514), ctypes.create_unicode_buffer(514),
                         ctypes.create_unicode_buffer(514))
    n_user, n_domain, n_pwd = wt.DWORD(514), wt.DWORD(514), wt.DWORD(514)
    try:
        if not _credui.CredUnPackAuthenticationBufferW(
                0, ctypes.c_void_p(cred.pointer), cred.size, user, ctypes.byref(n_user),
                domain, ctypes.byref(n_domain), pwd, ctypes.byref(n_pwd)):
            return False
        token = wt.HANDLE()
        if not _advapi32.LogonUserW(user.value, domain.value or ".", pwd.value,
                                    _LOGON32_LOGON_INTERACTIVE, _LOGON32_PROVIDER_DEFAULT,
                                    ctypes.byref(token)):
            return False
        try:
            return _token_is_current_user(token)
        finally:
            _kernel32.CloseHandle(token)
    finally:
        ctypes.memset(pwd, 0, ctypes.sizeof(pwd))


def _validate(cred: _Credential) -> bool:
    verdict = _validate_with_lsa(cred)
    return _validate_with_logonuser(cred) if verdict is None else verdict


def verify_current_user(title: str, message: str, *, parent_window_title: Optional[str] = None,
                        max_attempts: int = _MAX_ATTEMPTS) -> AuthResult:
    """
    Challenge the signed-in Windows user for their account password or PIN.
    Blocks until the user succeeds, cancels, or runs out of attempts. Never raises.
    """
    global _last_failure_at
    if not IS_WINDOWS:
        return AuthResult(False, UNAVAILABLE, "Windows account verification is only available on Windows.")
    if time.monotonic() - _last_failure_at < _COOLDOWN_SECONDS:
        return AuthResult(False, BUSY, "Too many failed attempts. Wait a few seconds and try again.")
    if not _prompt_lock.acquire(blocking=False):
        return AuthResult(False, BUSY, "A verification prompt is already open.")
    try:
        for attempt in range(max_attempts):
            cred = None
            try:
                cred = _show_prompt(title, message, parent_window_title,
                                    0 if attempt == 0 else _ERROR_LOGON_FAILURE)
                if cred is None:
                    return AuthResult(False, CANCELLED, "Verification cancelled.")
                if _validate(cred):
                    return AuthResult(True, OK)
            except OSError as exc:
                logger.error("Credential prompt failed: %s", exc)
                return AuthResult(False, ERROR, "Windows could not show the verification prompt.")
            finally:
                if cred is not None:
                    cred.wipe()
        _last_failure_at = time.monotonic()
        return AuthResult(False, FAILED, "Incorrect password or PIN.")
    finally:
        _prompt_lock.release()
