"""Read-only checks of Windows: Defender, startup items, tasks, processes, network, wallet files."""

import ctypes
import json
import os
import re
import subprocess
import winreg

from . import known
from .findings import Finding

SUSPICIOUS_DIRS = re.compile(r"\\(AppData\\(Local\\Temp|Roaming)|Temp|ProgramData|Users\\Public)\\", re.I)
SCRIPT_HOSTS = re.compile(r"\b(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?\b", re.I)
ENCODED = re.compile(r"(-enc(odedcommand)?\s|frombase64string|iex\s*\(|downloadstring|invoke-expression)", re.I)


def ps_json(script, timeout=60):
    """Run PowerShell and parse its ConvertTo-Json output. Returns [] / {} on failure."""
    cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
           f"$ErrorActionPreference='SilentlyContinue'; {script} | ConvertTo-Json -Depth 4 -Compress"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = r.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def exe_from_command(cmd):
    cmd = (cmd or "").strip()
    if cmd.startswith('"'):
        return cmd[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.(exe|cmd|bat|vbs|js|ps1|dll|lnk))\b", cmd, re.I)
    return m.group(1) if m else cmd.split(" ")[0]


def signatures(paths):
    """Map path -> Authenticode status ('Valid', 'NotSigned', ...) for existing files."""
    paths = sorted({p for p in paths if p and os.path.isfile(p)})
    if not paths:
        return {}
    quoted = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
    res = ps_json(f"@({quoted}) | % {{ $s=Get-AuthenticodeSignature -LiteralPath $_; "
                  f"[pscustomobject]@{{p=$_; s=[string]$s.Status; c=[string]$s.SignerCertificate.Subject}} }}",
                  timeout=120)
    return {r["p"].lower(): (r.get("s"), r.get("c")) for r in as_list(res) if isinstance(r, dict)}


# ---------------------------------------------------------------- Defender

def check_defender():
    f = []
    st = ps_json("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,BehaviorMonitorEnabled,"
                 "AntivirusEnabled,IsTamperProtected,AntivirusSignatureAge,FullScanAge,QuickScanAge")
    if not isinstance(st, dict):
        return [Finding("medium", "defender", "Could not read Microsoft Defender status",
                        "Another antivirus may be installed, or Defender is disabled.")]
    for key, label in (("RealTimeProtectionEnabled", "Real-time protection"),
                       ("BehaviorMonitorEnabled", "Behavior monitoring"),
                       ("AntivirusEnabled", "Antivirus"),
                       ("IsTamperProtected", "Tamper protection")):
        if st.get(key) is False:
            f.append(Finding("high", "defender", f"{label} is OFF",
                             fix="Turn it on in Windows Security → Virus & threat protection."))
    age = st.get("AntivirusSignatureAge")
    if isinstance(age, int) and age > 3:
        f.append(Finding("medium", "defender", f"Virus definitions are {age} days old",
                         fix="Run Windows Update or Update-MpSignature."))
    full = st.get("FullScanAge")
    if not isinstance(full, int) or full > 30:
        f.append(Finding("low", "defender", "No full Defender scan in the last 30 days",
                         fix="Run a full or Offline scan from Windows Security → Scan options."))

    threats = as_list(ps_json("Get-MpThreatDetection | Select-Object InitialDetectionTime,ThreatID,"
                              "@{n='Resources';e={$_.Resources -join '; '}},ActionSuccess"))
    for t in threats:
        f.append(Finding("high", "defender", f"Defender detection (ThreatID {t.get('ThreatID')})",
                         t.get("Resources", ""),
                         fix="Open Windows Security → Protection history and confirm it was removed. "
                             "If it was a stealer, move funds to a NEW wallet from a clean device.",
                         data=t))

    cfa = ps_json("(Get-MpPreference).EnableControlledFolderAccess")
    if cfa in (0, None):
        f.append(Finding("low", "defender", "Controlled Folder Access (ransomware protection) is off",
                         fix="Windows Security → Ransomware protection → Controlled folder access."))
    return f


# ---------------------------------------------------------------- startup

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]


def startup_entries():
    out = []
    for hive, path in RUN_KEYS:
        try:
            k = winreg.OpenKey(hive, path)
        except OSError:
            continue
        i = 0
        while True:
            try:
                name, val, typ = winreg.EnumValue(k, i)
            except OSError:
                break
            i += 1
            if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(val, str):
                hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                out.append({"source": f"{hive_name}\\{path}", "name": name,
                            "command": os.path.expandvars(val)})
    links = []
    for folder in (os.path.join(known.ROAMING, r"Microsoft\Windows\Start Menu\Programs\Startup"),
                   os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp")):
        if os.path.isdir(folder):
            for fn in os.listdir(folder):
                if fn.lower() != "desktop.ini":
                    links.append({"source": folder, "name": fn, "command": os.path.join(folder, fn)})
    targets = resolve_shortcuts([e["command"] for e in links if e["command"].lower().endswith(".lnk")])
    for e in links:
        t = targets.get(e["command"].lower())
        if t:
            e["command"] = f'"{t[0]}" {t[1]}'.strip()
    return out + links


def resolve_shortcuts(paths):
    """Map .lnk path -> (target, arguments) so we judge what a shortcut runs, not where it sits."""
    if not paths:
        return {}
    quoted = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
    res = ps_json(f"$sh=New-Object -ComObject WScript.Shell; @({quoted}) | % {{ $l=$sh.CreateShortcut($_); "
                  f"[pscustomobject]@{{p=$_; t=$l.TargetPath; a=$l.Arguments}} }}")
    return {r["p"].lower(): (r.get("t") or "", r.get("a") or "")
            for r in as_list(res) if isinstance(r, dict) and r.get("t")}


def scheduled_tasks():
    res = ps_json("Get-ScheduledTask | ?{ $_.TaskPath -notlike '\\Microsoft\\*' } | % { "
                  "[pscustomobject]@{name=$_.TaskPath+$_.TaskName; state=[string]$_.State; "
                  "command=(($_.Actions | %{ ($_.Execute + ' ' + $_.Arguments).Trim() }) -join ' | ')} }")
    return [t for t in as_list(res) if isinstance(t, dict) and t.get("command")]


def _assess_command(cmd, sig):
    reasons = []
    exe = exe_from_command(cmd)
    if ENCODED.search(cmd):
        reasons.append("runs an encoded/downloaded PowerShell command")
    if SUSPICIOUS_DIRS.search(exe):
        reasons.append("runs from a user-writable folder (AppData/Temp/ProgramData)")
    if SCRIPT_HOSTS.search(os.path.basename(exe)) and ("-windowstyle hidden" in cmd.lower() or "bypass" in cmd.lower()):
        reasons.append("hidden or policy-bypassing script launcher")
    if sig and sig[0] and sig[0] != "Valid" and exe.lower().endswith(".exe"):
        reasons.append(f"executable is not validly signed ({sig[0]})")
    if exe and not os.path.exists(exe) and ("\\" in exe):
        reasons.append("target file is missing")
    return reasons


def _severity(reasons):
    if any("encoded" in r for r in reasons) or len(reasons) >= 2:
        return "high"
    if reasons == ["target file is missing"]:
        return "low"  # leftover from an uninstall; harmless but worth cleaning
    return "medium"


def check_persistence(entries=None, tasks=None):
    entries = startup_entries() if entries is None else entries
    tasks = scheduled_tasks() if tasks is None else tasks
    sigs = signatures([exe_from_command(e["command"]) for e in entries] +
                      [exe_from_command(t["command"].split(" | ")[0]) for t in tasks])
    f = []
    for e in entries:
        if e["name"] == "WalletGuard" and "WalletGuard.pyw" in e["command"]:
            continue  # ourselves
        exe = exe_from_command(e["command"])
        reasons = _assess_command(e["command"], sigs.get(exe.lower()))
        if reasons:
            f.append(Finding(_severity(reasons), "startup", f"Startup item: {e['name']}", "; ".join(reasons),
                             fix="If you don't recognise it, disable it in Task Manager → Startup apps and scan the file.",
                             data=e))
    for t in tasks:
        first = t["command"].split(" | ")[0]
        reasons = _assess_command(t["command"], sigs.get(exe_from_command(first).lower()))
        if reasons:
            f.append(Finding(_severity(reasons), "task", f"Scheduled task: {t['name']}", "; ".join(reasons),
                             fix="If you don't recognise it, disable it in Task Scheduler and scan the file.",
                             data=t))
    return f


# ---------------------------------------------------------------- processes & network

def check_processes():
    procs = as_list(ps_json("Get-Process | ?{ $_.Path } | Select-Object Id,ProcessName,Path"))
    sus = [p for p in procs if isinstance(p, dict) and SUSPICIOUS_DIRS.search(p.get("Path", ""))]
    sigs = signatures([p["Path"] for p in sus])
    conns = as_list(ps_json("Get-NetTCPConnection -State Established | "
                            "?{ $_.RemoteAddress -notmatch '^(127\\.|::1|0\\.0\\.0\\.0)' } | "
                            "Select-Object OwningProcess,RemoteAddress,RemotePort"))
    remote_by_pid = {}
    for c in conns:
        if isinstance(c, dict):
            remote_by_pid.setdefault(c.get("OwningProcess"), []).append(f"{c.get('RemoteAddress')}:{c.get('RemotePort')}")
    f, seen = [], set()
    for p in sus:
        path = p["Path"]
        if path.lower() in seen:
            continue
        seen.add(path.lower())
        status, subject = sigs.get(path.lower(), (None, None))
        if status == "Valid":
            continue
        remotes = remote_by_pid.get(p.get("Id"), [])
        sev = "high" if remotes else "medium"
        f.append(Finding(sev, "process", f"Unsigned program running from a user folder: {p['ProcessName']}",
                         f"{path}" + (f" — connected to {', '.join(remotes[:5])}" if remotes else ""),
                         fix="Check what this is. Upload it to virustotal.com if unsure.",
                         data={"path": path, "signature": status, "remotes": remotes}))
    return f


# ---------------------------------------------------------------- browser launch tampering

shell32 = ctypes.WinDLL("shell32")
shell32.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]


def split_command_line(cmd):
    """Tokenise exactly as Windows does (CommandLineToArgvW), not by guessing on substrings."""
    if not cmd or not cmd.strip():
        return []
    n = ctypes.c_int()
    argv = shell32.CommandLineToArgvW(cmd, ctypes.byref(n))
    if not argv:
        return []
    try:
        return [argv[i] for i in range(n.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(argv)


def browser_shortcut_dirs():
    roam, prog = known.ROAMING, os.environ.get("ProgramData", "")
    home = os.environ.get("USERPROFILE", "")
    return [
        os.path.join(home, "Desktop"),
        os.path.join(home, "OneDrive", "Desktop"),
        os.path.join(os.environ.get("PUBLIC", ""), "Desktop"),
        os.path.join(roam, r"Microsoft\Windows\Start Menu"),
        os.path.join(prog, r"Microsoft\Windows\Start Menu"),
        os.path.join(roam, r"Microsoft\Internet Explorer\Quick Launch"),
    ]


def browser_launch_points():
    """(where, command line) for every shortcut and Run entry that starts a browser."""
    lnks = []
    for d in browser_shortcut_dirs():
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            lnks += [os.path.join(root, f) for f in files if f.lower().endswith(".lnk")]
    points = []
    for lnk, (target, args) in resolve_shortcuts(lnks).items():
        if os.path.basename(target).lower() in known.BROWSER_EXES:
            points.append((lnk, f'"{target}" {args}'.strip()))
    for e in startup_entries():
        if os.path.basename(exe_from_command(e["command"])).lower() in known.BROWSER_EXES:
            points.append((f"{e['source']}\\{e['name']}", e["command"]))
    return points


def check_browser_launch(points=None):
    from .security.browser_launch import analyze_arguments
    points = browser_launch_points() if points is None else points
    f = []
    for where, cmd in points:
        for finding in analyze_arguments(split_command_line(cmd)[1:]):
            # Outside a dev folder, these flags on a shortcut are a known stealer trick for
            # loading a malicious extension or remote-controlling the browser.
            dev = where.lower().startswith(r"c:\dev")
            f.append(Finding("medium" if dev else "high", "browser-launch",
                             f"{finding.title}: {os.path.basename(where)}",
                             f"{where} starts the browser with {finding.data.get('flag')}. "
                             "Malware adds these flags to load a hidden extension or take control of the browser.",
                             fix=finding.fix + " If you didn't add it, delete and recreate the shortcut.",
                             data={"where": where, "command": cmd}))
    return f


def check_desktop_wallets():
    f = []
    for base in (known.ROAMING, known.LOCAL):
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for d in names:
            if any(d.lower() == w.lower() for w in known.DESKTOP_WALLET_DIRS):
                f.append(Finding("info", "wallet", f"Desktop wallet data found: {d}", os.path.join(base, d),
                                 fix="Stealers copy this folder. Keep the wallet password-protected and back up the seed offline."))
    return f


def scan_system():
    findings = []
    for check in (check_defender, check_persistence, check_browser_launch, check_processes, check_desktop_wallets):
        try:
            findings += check()
        except Exception as e:  # one broken check must not hide the rest
            findings.append(Finding("low", "scanner", f"{check.__name__} failed", repr(e)))
    return findings
