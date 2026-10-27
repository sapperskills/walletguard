"""Windows clipboard history and cloud clipboard: everything you copy is kept, and can sync.

This module is also the worked example in docs/WRITING_A_DETECTOR.md: a collector that reads
Windows state, a pure `assess()` that turns it into findings, and `check()` joining the two.
"""

import winreg

from .findings import Finding

KEY = r"Software\Microsoft\Clipboard"


def read_settings():
    """Collector: read the raw values. Missing values mean Windows' default (off)."""
    out = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY) as k:
            for name in ("EnableClipboardHistory", "EnableCloudClipboard", "CloudClipboardAutomaticUpload"):
                try:
                    out[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    pass
    except OSError:
        pass
    return out


def assess(settings):
    """Pure logic: settings dict -> findings. Unit-tested without touching the registry."""
    history = settings.get("EnableClipboardHistory") == 1
    cloud = settings.get("EnableCloudClipboard") == 1
    auto_upload = settings.get("CloudClipboardAutomaticUpload") == 1
    if cloud and auto_upload:
        return [Finding(
            "medium", "clipboard", "Cloud clipboard uploads everything you copy",
            "Clipboard sync is on with automatic upload, so anything you copy (a seed phrase, a private key, "
            "a password) is sent to your Microsoft account and other devices.",
            fix="Settings → System → Clipboard: turn off 'Clipboard history across your devices', or set it to "
                "'Manually sync text that I copy'. Never copy a seed phrase at all.")]
    if history:
        return [Finding(
            "low", "clipboard", "Clipboard history is on",
            "Windows keeps the last 25 things you copied (Win+V). A copied seed phrase or key stays there "
            "until you clear it, where malware or anyone at the PC can read it.",
            fix="If you ever copied a seed phrase or key, press Win+V → Clear all. Better: never copy them.")]
    return []


def check():
    return assess(read_settings())
