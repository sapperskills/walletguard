"""Extensions the user didn't install themselves: forced by policy, planted via the registry,
loaded unpacked or from the command line, and developer mode left on.

Malware uses browser policies to install an extension the user can't remove, and loads
"unpacked" copies (sometimes reusing a real wallet's ID) to sit next to the wallet.
"""

import json
import os
import winreg

from . import known
from .findings import Finding

POLICY_KEYS = {
    "Chrome": r"SOFTWARE\Policies\Google\Chrome",
    "Edge": r"SOFTWARE\Policies\Microsoft\Edge",
    "Brave": r"SOFTWARE\Policies\BraveSoftware\Brave",
}
EXTERNAL_KEYS = {
    "Chrome": [r"SOFTWARE\Google\Chrome\Extensions", r"SOFTWARE\WOW6432Node\Google\Chrome\Extensions"],
    "Edge": [r"SOFTWARE\Microsoft\Edge\Extensions", r"SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions"],
    "Brave": [r"SOFTWARE\BraveSoftware\Brave-Browser\Extensions"],
}
FIREFOX_POLICY_FILES = [
    os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), r"Mozilla Firefox\distribution\policies.json"),
    os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), r"Mozilla Firefox\distribution\policies.json"),
]
HIVES = (("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER))

# Chromium's Manifest::Location values stored in Preferences.
LOCATION_UNPACKED = 4
LOCATION_COMMAND_LINE = 8
LOCATION_POLICY = {7, 9}
LOCATION_COMPONENT = {5, 10}


def is_managed_pc():
    """Work PCs legitimately force-install extensions; home PCs almost never do."""
    return bool(os.environ.get("USERDNSDOMAIN"))


def from_store_url(url):
    return any(u in (url or "") for u in known.STORE_UPDATE_URLS)


# ---------------------------------------------------------------- collectors

def _values(hive, path):
    try:
        k = winreg.OpenKey(hive, path)
    except OSError:
        return {}
    out, i = {}, 0
    while True:
        try:
            name, val, _ = winreg.EnumValue(k, i)
        except OSError:
            return out
        out[name] = val
        i += 1


def _subkeys(hive, path):
    try:
        k = winreg.OpenKey(hive, path)
    except OSError:
        return []
    out, i = [], 0
    while True:
        try:
            out.append(winreg.EnumKey(k, i))
        except OSError:
            return out
        i += 1


def parse_forcelist_entry(value):
    """'id;update_url' or just 'id' -> (id, update_url)."""
    ext_id, _, url = str(value).partition(";")
    return ext_id.strip(), url.strip()


def parse_extension_settings(raw):
    """ExtensionSettings policy JSON -> [(id, mode, update_url)] for installs it forces or suggests."""
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return []
    out = []
    for key, cfg in (data or {}).items():
        if not isinstance(cfg, dict) or key == "*" or key.startswith("update_url:"):
            continue
        mode = cfg.get("installation_mode", "")
        if mode in ("force_installed", "normal_installed"):
            for ext_id in key.split(","):
                out.append((ext_id.strip(), mode, cfg.get("update_url", "") or cfg.get("install_url", "")))
    return out


def policy_installs():
    """Every extension a policy installs, across Chromium browsers and Firefox."""
    out = []
    for browser, path in POLICY_KEYS.items():
        for hive_name, hive in HIVES:
            for val in _values(hive, path + r"\ExtensionInstallForcelist").values():
                ext_id, url = parse_forcelist_entry(val)
                out.append({"browser": browser, "where": f"{hive_name}\\{path}\\ExtensionInstallForcelist",
                            "id": ext_id, "mode": "force_installed", "update_url": url})
            raw = _values(hive, path).get("ExtensionSettings")
            for ext_id, mode, url in parse_extension_settings(raw):
                out.append({"browser": browser, "where": f"{hive_name}\\{path}\\ExtensionSettings",
                            "id": ext_id, "mode": mode, "update_url": url})
    for f in FIREFOX_POLICY_FILES:
        try:
            with open(f, encoding="utf-8") as fh:
                pol = json.load(fh).get("policies", {})
        except (OSError, ValueError):
            continue
        for ext_id, mode, url in parse_extension_settings(pol.get("ExtensionSettings")):
            out.append({"browser": "Firefox", "where": f, "id": ext_id, "mode": mode, "update_url": url})
        for url in (pol.get("Extensions") or {}).get("Install", []):
            out.append({"browser": "Firefox", "where": f, "id": url, "mode": "force_installed", "update_url": url})
    for hive_name, hive in HIVES:
        ff = r"SOFTWARE\Policies\Mozilla\Firefox"
        for ext_id, mode, url in parse_extension_settings(_values(hive, ff).get("ExtensionSettings")):
            out.append({"browser": "Firefox", "where": f"{hive_name}\\{ff}", "id": ext_id, "mode": mode, "update_url": url})
        for url in _values(hive, ff + r"\Extensions\Install").values():
            out.append({"browser": "Firefox", "where": f"{hive_name}\\{ff}\\Extensions\\Install",
                        "id": str(url), "mode": "force_installed", "update_url": str(url)})
    return out


def external_installs():
    """Extensions registered for install by other software (HKLM/HKCU ...\\Extensions\\<id>)."""
    out = []
    for browser, paths in EXTERNAL_KEYS.items():
        for path in paths:
            for hive_name, hive in HIVES:
                for ext_id in _subkeys(hive, path):
                    v = _values(hive, f"{path}\\{ext_id}")
                    if not v.get("update_url") and not v.get("path"):
                        continue  # an empty key installs nothing (often a leftover from an uninstall)
                    out.append({"browser": browser, "where": f"{hive_name}\\{path}\\{ext_id}", "id": ext_id,
                                "update_url": v.get("update_url", ""), "path": v.get("path", "")})
    return out


def profile_states(browsers=None):
    """Per Chromium profile: developer mode, and how each extension was installed."""
    browsers = browsers if browsers is not None else known.CHROMIUM_BROWSERS
    out = []
    for browser, root in browsers.items():
        if not os.path.isdir(root):
            continue
        for d in os.listdir(root):
            pdir = os.path.join(root, d)
            prefs = {}
            for name in ("Preferences", "Secure Preferences"):
                try:
                    with open(os.path.join(pdir, name), encoding="utf-8") as fh:
                        data = json.load(fh)
                except (OSError, ValueError):
                    continue
                ext = data.get("extensions") or {}
                if (ext.get("ui") or {}).get("developer_mode"):
                    prefs["developer_mode"] = True
                for ext_id, s in (ext.get("settings") or {}).items():
                    if isinstance(s, dict):
                        prefs.setdefault("settings", {}).setdefault(ext_id, {}).update(s)
            if prefs:
                out.append({"browser": browser, "profile": d, "developer_mode": prefs.get("developer_mode", False),
                            "settings": prefs.get("settings", {})})
    return out


# ---------------------------------------------------------------- assessment

def _ext_name(ext_id):
    return known.WALLET_EXTENSIONS.get(ext_id) or known.FIREFOX_WALLETS.get(ext_id) or ext_id


def assess_policy_install(p, managed):
    store = from_store_url(p["update_url"]) or p["browser"] == "Firefox" and "addons.mozilla.org" in p["update_url"]
    if managed:
        sev = "medium" if store else "high"
    else:
        sev = "high" if store else "critical"
    detail = (f"{p['where']} makes {p['browser']} install {_ext_name(p['id'])} ({p['mode'].replace('_', ' ')}) "
              f"from {p['update_url'] or 'its default source'}. You can't remove an extension installed this way. ")
    detail += ("This PC is on a work domain, so your IT team may have set it." if managed else
               "Home PCs almost never have this; malware uses it to keep a malicious extension installed.")
    return Finding(sev, "policy", f"{p['browser']}: extension forced by policy ({_ext_name(p['id'])})", detail,
                   fix="If you didn't set this, delete the policy value in regedit (or the policies.json entry), "
                       "remove the extension, then run a Defender Offline scan.",
                   data=p)


def assess_external_install(e):
    risky = bool(e.get("path")) or not from_store_url(e.get("update_url"))
    return Finding("high" if risky else "low", "policy",
                   f"{e['browser']}: extension registered by other software ({_ext_name(e['id'])})",
                   f"{e['where']} tells {e['browser']} to install this extension"
                   + (f" from a local file ({e['path']})." if e.get("path") else
                      f" from {e.get('update_url') or 'an unknown source'}.")
                   + (" Antivirus and password managers do this legitimately." if not risky else
                      " Installing from outside the web store is a common malware technique."),
                   fix="If you don't recognise the extension, delete this registry key and remove the extension.",
                   data=e)


def assess_profile(state, wallet_profiles):
    findings = []
    where = f"{state['browser']} '{state['profile']}'"
    has_wallet = (state["browser"], state["profile"]) in wallet_profiles
    for ext_id, s in state["settings"].items():
        loc = s.get("location")
        if loc in LOCATION_COMPONENT or loc in LOCATION_POLICY:
            continue
        is_wallet_id = ext_id in known.WALLET_EXTENSIONS
        if loc in (LOCATION_UNPACKED, LOCATION_COMMAND_LINE):
            how = "unpacked from a folder" if loc == LOCATION_UNPACKED else "from the browser's command line"
            sev = "critical" if is_wallet_id else ("high" if has_wallet else "medium")
            title = (f"{where}: a copy of {_ext_name(ext_id)} is loaded {how}" if is_wallet_id
                     else f"{where}: extension loaded {how}")
            findings.append(Finding(
                sev, "policy", title,
                f"Extension {ext_id} at {s.get('path', '?')} did not come from a web store."
                + (" A wallet loaded this way is not the real one; stealers do this to capture your password and seed."
                   if is_wallet_id else " Developers do this; malware does too, to slip in an extension without review."),
                fix="Remove it in the browser's extensions page unless you are developing it. "
                    "If it's a wallet, reinstall the wallet from the official store on a clean PC.",
                data={"id": ext_id, "location": loc, "path": s.get("path")}))
        elif is_wallet_id and s.get("from_webstore") is False and loc not in (None, 1):
            findings.append(Finding(
                "high", "policy", f"{where}: {_ext_name(ext_id)} was not installed from the web store",
                f"Install location code {loc}.", fix="Reinstall the wallet from the official web store.",
                data={"id": ext_id, "location": loc}))
    if state["developer_mode"]:
        findings.append(Finding(
            "medium" if has_wallet else "low", "policy", f"{where}: developer mode is on",
            "Developer mode lets unpacked extensions run without store review."
            + (" This profile holds a wallet." if has_wallet else ""),
            fix="Turn off Developer mode on the browser's extensions page unless you need it."))
    return findings


def scan_policies(policies=None, externals=None, states=None, wallet_profiles=None, managed=None):
    from . import extensions
    managed = is_managed_pc() if managed is None else managed
    if wallet_profiles is None:
        wallet_profiles = {(e.browser, e.profile) for e in extensions.chromium_extensions() if e.is_wallet}
    f = [assess_policy_install(p, managed) for p in (policy_installs() if policies is None else policies)]
    f += [assess_external_install(e) for e in (external_installs() if externals is None else externals)]
    for s in (profile_states() if states is None else states):
        f += assess_profile(s, wallet_profiles)
    return f
