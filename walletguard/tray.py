"""System-tray app: runs the clipboard guard and extension watcher quietly in the background.

Pure ctypes (Shell_NotifyIconW), so it needs nothing beyond the standard library.
"""

import ctypes
import ctypes.wintypes as wt
import os
import threading
import time

from . import __version__, alerts, feeds, scanner, watcher
from .alerts import DATA_DIR, LOG_PATH, log_event

user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_APP = 0x8000
WM_TRAY = WM_APP + 1
WM_NOTIFY_REQ = WM_APP + 2

NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x1, 0x2, 0x4, 0x10
NIIF_INFO, NIIF_WARNING, NIIF_ERROR = 0x1, 0x2, 0x3

MF_STRING, MF_GRAYED, MF_SEPARATOR = 0x0, 0x1, 0x800
TPM_RIGHTBUTTON, TPM_RETURNCMD, TPM_NONOTIFY = 0x2, 0x100, 0x80

IDI_SHIELD = 32518
IDI_WARNING = 32515

CMD_PAUSE, CMD_SCAN, CMD_LOG, CMD_REPORTS, CMD_FEEDS, CMD_EXIT = range(1, 7)
FEED_REFRESH_SECONDS = 6 * 3600
MUTEX_NAME = "Local\\WalletGuardTray"


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD), ("Data4", ctypes.c_ubyte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD), ("hWnd", wt.HWND), ("uID", wt.UINT), ("uFlags", wt.UINT),
        ("uCallbackMessage", wt.UINT), ("hIcon", wt.HICON), ("szTip", wt.WCHAR * 128),
        ("dwState", wt.DWORD), ("dwStateMask", wt.DWORD), ("szInfo", wt.WCHAR * 256),
        ("uTimeoutOrVersion", wt.UINT), ("szInfoTitle", wt.WCHAR * 64), ("dwInfoFlags", wt.DWORD),
        ("guidItem", GUID), ("hBalloonIcon", wt.HICON),
    ]


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.UINT), ("style", wt.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int), ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON),
        ("hCursor", wt.HANDLE), ("hbrBackground", wt.HBRUSH), ("lpszMenuName", wt.LPCWSTR),
        ("lpszClassName", wt.LPCWSTR), ("hIconSm", wt.HICON),
    ]


user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
user32.RegisterClassExW.restype = wt.ATOM
user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID]
user32.CreateWindowExW.restype = wt.HWND
user32.LoadIconW.argtypes = [wt.HINSTANCE, wt.LPVOID]
user32.LoadIconW.restype = wt.HICON
user32.CreatePopupMenu.restype = wt.HMENU
user32.AppendMenuW.argtypes = [wt.HMENU, wt.UINT, ctypes.c_size_t, wt.LPCWSTR]
user32.TrackPopupMenu.argtypes = [wt.HMENU, wt.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.HWND, wt.LPVOID]
user32.TrackPopupMenu.restype = ctypes.c_int
user32.DestroyMenu.argtypes = [wt.HMENU]
user32.SetForegroundWindow.argtypes = [wt.HWND]
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.RegisterWindowMessageW.argtypes = [wt.LPCWSTR]
user32.RegisterWindowMessageW.restype = wt.UINT
user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
user32.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
user32.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
user32.DestroyWindow.argtypes = [wt.HWND]
shell32.Shell_NotifyIconW.argtypes = [wt.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
shell32.Shell_NotifyIconW.restype = wt.BOOL
kernel32.CreateMutexW.argtypes = [wt.LPVOID, wt.BOOL, wt.LPCWSTR]
kernel32.CreateMutexW.restype = wt.HANDLE
kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
kernel32.GetModuleHandleW.restype = wt.HMODULE

ERROR_ALREADY_EXISTS = 183


def already_running():
    """Hold a named mutex for the life of the process; True if another tray owns it."""
    global _mutex
    _mutex = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    return ctypes.get_last_error() == ERROR_ALREADY_EXISTS


class TrayApp:
    def __init__(self, kill=False, interval=60, offline=False):
        from .clipboard import ClipboardGuard
        self.kill = kill
        self.interval = interval
        self.offline = offline
        self.stop = threading.Event()
        self.guard = ClipboardGuard(None, kill=kill)
        self.hwnd = None
        self._pending = []           # balloons queued from worker threads
        self._pending_lock = threading.Lock()
        self._scanning = False
        self._wndproc = WNDPROC(self._proc)  # keep a reference so it isn't garbage-collected
        self.icon_ok = user32.LoadIconW(None, ctypes.c_void_p(IDI_SHIELD))
        self.icon_paused = user32.LoadIconW(None, ctypes.c_void_p(IDI_WARNING))

    # ------------------------------------------------------------ icon

    def _nid(self):
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        return nid

    def _tooltip(self):
        state = "PAUSED" if self.guard.paused.is_set() else "protecting"
        return f"WalletGuard {__version__} — {state}"

    def _add_icon(self):
        nid = self._nid()
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = self.icon_ok
        nid.szTip = self._tooltip()
        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))

    def _refresh_icon(self):
        nid = self._nid()
        nid.uFlags = NIF_ICON | NIF_TIP
        nid.hIcon = self.icon_paused if self.guard.paused.is_set() else self.icon_ok
        nid.szTip = self._tooltip()
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

    def _show_balloon(self, title, text, level):
        nid = self._nid()
        nid.uFlags = NIF_INFO
        nid.szInfoTitle = title[:63]
        nid.szInfo = text[:255]
        nid.dwInfoFlags = level
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

    def notify(self, title, text, critical=False):
        """Thread-safe: queue a balloon and wake the UI thread to show it."""
        with self._pending_lock:
            self._pending.append((title, text, NIIF_ERROR if critical else NIIF_WARNING))
        if self.hwnd:
            user32.PostMessageW(self.hwnd, WM_NOTIFY_REQ, 0, 0)

    # ------------------------------------------------------------ menu

    def _menu(self):
        m = user32.CreatePopupMenu()
        paused = self.guard.paused.is_set()
        user32.AppendMenuW(m, MF_STRING | MF_GRAYED, 0, self._tooltip())
        user32.AppendMenuW(m, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(m, MF_STRING, CMD_PAUSE, "Resume clipboard guard" if paused else "Pause clipboard guard")
        user32.AppendMenuW(m, MF_STRING | (MF_GRAYED if self._scanning else 0), CMD_SCAN,
                           "Scanning…" if self._scanning else "Run security scan now")
        user32.AppendMenuW(m, MF_STRING, CMD_FEEDS, "Update threat feeds")
        user32.AppendMenuW(m, MF_STRING, CMD_LOG, "Open event log")
        user32.AppendMenuW(m, MF_STRING, CMD_REPORTS, "Open reports folder")
        user32.AppendMenuW(m, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(m, MF_STRING, CMD_EXIT, "Exit WalletGuard")
        pt = wt.POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(self.hwnd)  # so the menu closes when you click elsewhere
        cmd = user32.TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, self.hwnd, None)
        user32.DestroyMenu(m)
        if cmd:
            self._command(cmd)

    def _command(self, cmd):
        if cmd == CMD_PAUSE:
            if self.guard.paused.is_set():
                self.guard.paused.clear()
                log_event("guard_resumed")
            else:
                self.guard.paused.set()
                log_event("guard_paused")
                self.notify("Clipboard guard paused", "Address swaps are NOT being blocked until you resume.")
            self._refresh_icon()
        elif cmd == CMD_SCAN:
            threading.Thread(target=self._scan, daemon=True).start()
        elif cmd == CMD_FEEDS:
            threading.Thread(target=self._refresh_feeds, args=(True,), daemon=True).start()
        elif cmd == CMD_LOG:
            _open(LOG_PATH)
        elif cmd == CMD_REPORTS:
            _open(DATA_DIR)
        elif cmd == CMD_EXIT:
            user32.DestroyWindow(self.hwnd)

    # ------------------------------------------------------------ workers

    def _scan(self):
        from .report import write_reports
        self._scanning = True
        try:
            findings = scanner.full_scan()
            txt, _ = write_reports(findings)
            bad = sum(1 for f in findings if f.severity in ("critical", "high"))
            self.notify("Scan finished",
                        f"{bad} high-risk item(s) found. Opening the report." if bad else "No high-risk items found.",
                        critical=bool(bad))
            if bad:
                _open(txt)
        except Exception as e:
            log_event("tray_scan_error", error=repr(e))
            self.notify("Scan failed", repr(e)[:200])
        finally:
            self._scanning = False

    def _refresh_feeds(self, force=False):
        if not self.offline or force:
            feeds.update(force=force)
        intel = feeds.ThreatIntel.load()
        self.guard.policy.intel = intel if intel.loaded else None
        if force:
            self.notify("Threat feeds updated",
                        f"{len(intel.addresses)} scam addresses, {len(intel.domains)} phishing domains.")

    def _feed_loop(self):
        while not self.stop.is_set():
            try:
                self._refresh_feeds()
            except Exception as e:
                log_event("feed_refresh_error", error=repr(e))
            self.stop.wait(FEED_REFRESH_SECONDS)

    # ------------------------------------------------------------ window

    def _proc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_TRAY:
                if lparam == WM_RBUTTONUP:
                    self._menu()
                elif lparam == WM_LBUTTONDBLCLK:
                    self.notify(self._tooltip(), "Right-click the shield for options.")
                return 0
            if msg == WM_NOTIFY_REQ:
                with self._pending_lock:
                    items, self._pending = self._pending, []
                for title, text, level in items[-3:]:
                    self._show_balloon(title, text, level)
                return 0
            if msg == self._taskbar_created:
                self._add_icon()  # Explorer restarted; put the icon back
                return 0
            if msg == WM_CLOSE:
                user32.DestroyWindow(hwnd)
                return 0
            if msg == WM_DESTROY:
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid()))
                self.stop.set()
                log_event("tray_exit")
                user32.PostQuitMessage(0)
                return 0
        except Exception as e:
            log_event("tray_error", error=repr(e))
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def run(self):
        hinst = kernel32.GetModuleHandleW(None)
        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = hinst
        wc.lpszClassName = "WalletGuardTray"
        user32.RegisterClassExW(ctypes.byref(wc))
        self._taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")
        self.hwnd = user32.CreateWindowExW(0, "WalletGuardTray", "WalletGuard", 0, 0, 0, 0, 0,
                                           None, None, hinst, None)
        self._add_icon()

        # Route watcher/guard alerts through the tray: critical ones still get the pop-up too.
        alerts.set_notifier(self.notify)

        threading.Thread(target=self._feed_loop, daemon=True).start()
        threading.Thread(target=watcher.run, args=(self.interval, self.stop), daemon=True).start()
        threading.Thread(target=self.guard.run, args=(self.stop,), daemon=True).start()
        log_event("tray_started", version=__version__, kill=self.kill)
        self.notify("WalletGuard is protecting you", "Clipboard guard and extension watcher are running.")

        msg = wt.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        self.stop.set()
        time.sleep(0.2)


def _open(path):
    try:
        os.startfile(path)
    except OSError:
        pass


def main(kill=False, interval=60, offline=False):
    if already_running():
        return 0
    try:
        TrayApp(kill=kill, interval=interval, offline=offline).run()
    except Exception as e:
        log_event("tray_crash", error=repr(e))
        raise
    return 0
