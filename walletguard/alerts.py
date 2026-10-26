"""Alerting: pop-up, sound, and an append-only event log."""

import ctypes
import datetime
import json
import os
import threading
import time

DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", "."), "WalletGuard")
LOG_PATH = os.path.join(DATA_DIR, "events.log")

MB_ICONWARNING = 0x30
MB_ICONERROR = 0x10
MB_SYSTEMMODAL = 0x1000
MB_SETFOREGROUND = 0x10000
MB_TOPMOST = 0x40000

_last_popup = {}
_lock = threading.Lock()
_notifier = None


def set_notifier(fn):
    """Install a tray notifier fn(title, message, critical). Non-critical alerts then use it
    instead of a pop-up; critical ones get both, because a balloon is too easy to miss."""
    global _notifier
    _notifier = fn


def log_event(kind, **fields):
    os.makedirs(DATA_DIR, exist_ok=True)
    rec = {"time": datetime.datetime.now().isoformat(timespec="seconds"), "kind": kind, **fields}
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def alert(title, message, critical=True, dedupe_key=None, quiet_seconds=10):
    """Show a top-most Windows pop-up without blocking the caller."""
    print(f"\n[!] {title}\n    {message.replace(chr(10), chr(10) + '    ')}\n", flush=True)
    key = dedupe_key or title
    with _lock:
        now = time.monotonic()
        if now - _last_popup.get(key, -1e9) < quiet_seconds:
            return
        _last_popup[key] = now

    if _notifier:
        try:
            _notifier(title, message.split("\n\n")[0], critical)
        except Exception:
            pass
        if not critical:
            return

    def show():
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONHAND if critical else winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass
        flags = (MB_ICONERROR if critical else MB_ICONWARNING) | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST
        ctypes.windll.user32.MessageBoxW(None, message, f"WalletGuard — {title}", flags)

    threading.Thread(target=show, daemon=True).start()
