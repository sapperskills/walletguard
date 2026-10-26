"""Start the tray app at logon via the current user's Run key (no admin needed)."""

import os
import subprocess
import sys
import winreg

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE = "WalletGuard"
LAUNCHER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "WalletGuard.pyw")


def pythonw():
    exe = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return exe if os.path.isfile(exe) else sys.executable


def command(kill=False):
    return f'"{pythonw()}" "{LAUNCHER}"' + (" --kill" if kill else "")


def install(kill=False):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, VALUE, 0, winreg.REG_SZ, command(kill))
    return command(kill)


def uninstall():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, VALUE)
        return True
    except FileNotFoundError:
        return False


def current():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            return winreg.QueryValueEx(k, VALUE)[0]
    except FileNotFoundError:
        return None


def inside_app_container():
    """True when started from inside a packaged desktop app (for example an AI coding agent in the
    Claude desktop app). Windows then silently redirects AppData and HKCU writes into that app's
    private storage, so reports and the Run entry would be invisible to the rest of Windows."""
    if os.environ.get("CLAUDECODE"):
        return True
    import ctypes
    n = ctypes.c_uint32(0)
    try:
        rc = ctypes.windll.kernel32.GetCurrentPackageFullName(ctypes.byref(n), None)
    except (AttributeError, OSError):
        return False
    return rc != 15700  # APPMODEL_ERROR_NO_PACKAGE


def start_now(kill=False):
    """Launch the tray detached from this console. A second copy exits on its own."""
    args = [pythonw(), LAUNCHER] + (["--kill"] if kill else [])
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen(args, creationflags=flags, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
