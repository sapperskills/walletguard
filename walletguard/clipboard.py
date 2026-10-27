"""Clipboard guard: catch and undo crypto-address swaps ("clippers").

A clipper waits for you to copy a wallet address and instantly replaces it with
the attacker's. People don't copy two different addresses of the same chain
within a second; malware does. When that happens we put your address back,
name the program that changed it, and alert.
"""

import ctypes
import ctypes.wintypes as wt
import os
import threading
import time
from dataclasses import dataclass

from . import addresses
from .alerts import alert, log_event
from .known import BROWSER_EXES

SWAP_WINDOW = 1.5  # seconds


@dataclass
class Verdict:
    action: str          # ok | restore | warn
    reason: str = ""
    original: str = ""
    replacement: str = ""
    chain: str = ""


class ClipboardPolicy:
    """Pure decision logic, kept free of Win32 so it can be unit-tested."""

    def __init__(self, intel=None, swap_window=SWAP_WINDOW):
        self.intel = intel
        self.swap_window = swap_window
        self.last_addr = None
        self.last_chain = None
        self.last_time = 0.0

    def observe(self, text, now):
        info = addresses.analyze(text) if text else None
        chain = info.chain if info else None
        if not chain:
            if text and self.intel:
                dom = self.intel.bad_domain(text)
                if dom:
                    return Verdict("warn", f"You copied a link to a known crypto phishing site ({dom}).")
            self.last_addr = None
            return Verdict("ok")

        addr = text.strip()
        prev, prev_chain, dt = self.last_addr, self.last_chain, now - self.last_time
        verdict = Verdict("ok", chain=chain)

        if prev and prev_chain == chain and addresses.normalise(prev) != addresses.normalise(addr):
            if dt < self.swap_window:
                # Keep remembering the user's address so a repeat swap is also undone.
                return Verdict("restore",
                               f"Your copied {chain} address was replaced {dt:.2f}s later — "
                               "too fast for a person. This is clipboard-hijacking malware.",
                               original=prev, replacement=addr, chain=chain)
            if addresses.lookalike(prev, addr):
                verdict = Verdict("warn",
                                  f"This {chain} address looks like the one you copied before "
                                  f"({addresses.short(prev)}) but is different. Address-poisoning scams "
                                  "use look-alike addresses. Check every character.",
                                  original=prev, replacement=addr, chain=chain)

        if info.checksum == "invalid":
            verdict = Verdict("warn",
                              f"This {chain} address has a broken checksum: some letters' upper/lower case is "
                              "wrong, so it was mistyped or altered. Don't send to it; copy it again from the source.",
                              replacement=addr, chain=chain)

        if self.intel and self.intel.bad_address(addr):
            verdict = Verdict("warn", f"This {chain} address is on a public scam list. Do NOT send funds to it.",
                              replacement=addr, chain=chain)

        self.last_addr, self.last_chain, self.last_time = addr, chain, now
        return verdict

    def restored(self, now):
        """We just put the user's address back; a clipper that swaps it again soon is caught again."""
        self.last_time = now


# ---------------------------------------------------------------- Win32

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

user32.GetClipboardSequenceNumber.restype = wt.DWORD
user32.OpenClipboard.argtypes = [wt.HWND]
user32.OpenClipboard.restype = wt.BOOL
user32.CloseClipboard.restype = wt.BOOL
user32.EmptyClipboard.restype = wt.BOOL
user32.GetClipboardData.argtypes = [wt.UINT]
user32.GetClipboardData.restype = wt.HANDLE
user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
user32.SetClipboardData.restype = wt.HANDLE
user32.GetClipboardOwner.restype = wt.HWND
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
user32.GetWindowThreadProcessId.restype = wt.DWORD
kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
kernel32.GlobalAlloc.restype = wt.HGLOBAL
kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
kernel32.GlobalFree.argtypes = [wt.HGLOBAL]
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
kernel32.CloseHandle.argtypes = [wt.HANDLE]


def _open_clipboard(retries=10):
    for _ in range(retries):
        if user32.OpenClipboard(None):
            return True
        time.sleep(0.02)
    return False


def get_text():
    if not _open_clipboard():
        return None
    try:
        h = user32.GetClipboardData(CF_UNICODETEXT)
        if not h:
            return None
        p = kernel32.GlobalLock(h)
        if not p:
            return None
        try:
            return ctypes.wstring_at(p)
        finally:
            kernel32.GlobalUnlock(h)
    finally:
        user32.CloseClipboard()


def set_text(text):
    data = ctypes.create_unicode_buffer(text)
    size = ctypes.sizeof(data)
    h = kernel32.GlobalAlloc(GMEM_MOVEABLE, size)
    if not h:
        return False
    p = kernel32.GlobalLock(h)
    ctypes.memmove(p, data, size)
    kernel32.GlobalUnlock(h)
    if not _open_clipboard():
        kernel32.GlobalFree(h)
        return False
    try:
        user32.EmptyClipboard()
        if not user32.SetClipboardData(CF_UNICODETEXT, h):
            kernel32.GlobalFree(h)
            return False
        return True  # the system owns h now
    finally:
        user32.CloseClipboard()


def clipboard_owner():
    """(pid, exe path) of the process that last wrote the clipboard, if known."""
    hwnd = user32.GetClipboardOwner()
    if not hwnd:
        return None, None
    pid = wt.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value, process_path(pid.value)


def process_path(pid):
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        n = wt.DWORD(1024)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
            return buf.value
        return None
    finally:
        kernel32.CloseHandle(h)


NEVER_KILL = BROWSER_EXES | {"explorer.exe", "python.exe", "pythonw.exe", "svchost.exe",
                             "csrss.exe", "winlogon.exe", "dwm.exe", "lsass.exe"}


def terminate(pid, path):
    name = os.path.basename(path or "").lower()
    if not path or name in NEVER_KILL or path.lower().startswith(os.environ.get("SystemRoot", r"C:\Windows").lower()):
        return False
    h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False
    try:
        return bool(kernel32.TerminateProcess(h, 1))
    finally:
        kernel32.CloseHandle(h)


class ClipboardGuard:
    def __init__(self, intel=None, kill=False, poll=0.05):
        self.policy = ClipboardPolicy(intel)
        self.kill = kill
        self.poll = poll
        self._ignore_seq = None
        self._last_seq = None
        self.paused = threading.Event()

    def step(self):
        seq = user32.GetClipboardSequenceNumber()
        if seq == self._last_seq:
            return
        self._last_seq = seq
        if seq == self._ignore_seq:
            return  # our own restore
        text = get_text()
        v = self.policy.observe(text, time.monotonic())
        if v.action == "ok":
            return
        pid, path = clipboard_owner()
        who = f"{os.path.basename(path)} (PID {pid})\n{path}" if path else "unknown (the program hid its window)"
        if v.action == "restore":
            restored = set_text(v.original)
            if restored:
                self._ignore_seq = user32.GetClipboardSequenceNumber()
                self._last_seq = self._ignore_seq
                self.policy.restored(time.monotonic())
            killed = terminate(pid, path) if (self.kill and pid) else False
            log_event("clipboard_swap_blocked", chain=v.chain, original=v.original, replacement=v.replacement,
                      owner_pid=pid, owner_path=path, restored=restored, killed=killed)
            alert("Clipboard hijack BLOCKED",
                  f"{v.reason}\n\nYour address:  {v.original}\nAttacker's:     {v.replacement}\n\n"
                  f"Program that changed it: {who}\n\n"
                  + ("Your original address has been put back. " if restored else "Could NOT restore — do not paste! ")
                  + ("The program was terminated. " if killed else "")
                  + "Assume this PC is infected: do not use wallets on it, run a Defender Offline scan, "
                    "and move funds to a NEW wallet from a clean device.",
                  critical=True, dedupe_key="swap")
        else:
            log_event("clipboard_warning", chain=v.chain, reason=v.reason, address=v.replacement,
                      owner_pid=pid, owner_path=path)
            alert("Check this address", f"{v.reason}\n\nCopied: {v.replacement or text}",
                  critical=False, dedupe_key="warn:" + (v.replacement or text or "")[:64])

    def run(self, stop_event=None):
        self._last_seq = user32.GetClipboardSequenceNumber()
        initial = get_text()
        if initial:
            self.policy.observe(initial, time.monotonic() - 60)
        while not (stop_event and stop_event.is_set()):
            if self.paused.is_set():
                # Forget history so resuming doesn't compare against a stale address.
                self._last_seq = user32.GetClipboardSequenceNumber()
                self.policy.last_addr = None
                time.sleep(0.25)
                continue
            try:
                self.step()
            except Exception as e:  # never let the guard die silently
                log_event("clipboard_error", error=repr(e))
            time.sleep(self.poll)
