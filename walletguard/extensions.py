"""Inventory browser extensions and score how dangerous each is to wallets in the same profile."""

import json
import os
from dataclasses import dataclass, field

from . import known
from .findings import Finding


@dataclass
class Extension:
    browser: str
    profile: str
    ext_id: str
    name: str
    version: str
    path: str
    permissions: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    content_matches: list = field(default_factory=list)
    update_url: str = ""

    @property
    def key(self):
        return f"{self.browser}/{self.profile}/{self.ext_id}"

    @property
    def is_wallet(self):
        return self.ext_id in known.WALLET_EXTENSIONS or self.ext_id in known.FIREFOX_WALLETS


def _resolve_msg(name, ext_dir, default_locale):
    """Turn '__MSG_appName__' into the real name using the extension's _locales."""
    if not name.startswith("__MSG_"):
        return name
    key = name[6:-2].lower()
    for loc in (default_locale, "en", "en_US"):
        if not loc:
            continue
        f = os.path.join(ext_dir, "_locales", loc, "messages.json")
        try:
            with open(f, encoding="utf-8-sig") as fh:
                msgs = json.load(fh)
        except (OSError, ValueError):
            continue
        for k, v in msgs.items():
            if k.lower() == key and isinstance(v, dict):
                return v.get("message", name)
    return name


def _latest_version_dir(ext_root):
    try:
        subs = [d for d in os.listdir(ext_root) if os.path.isdir(os.path.join(ext_root, d))]
    except OSError:
        return None
    if not subs:
        return None
    subs.sort(key=lambda s: [int(p) if p.isdigit() else 0 for p in s.split("_")[0].split(".")])
    return os.path.join(ext_root, subs[-1])


def read_chromium_extension(browser, profile, ext_id, ext_root):
    vdir = _latest_version_dir(ext_root)
    if not vdir:
        return None
    try:
        with open(os.path.join(vdir, "manifest.json"), encoding="utf-8-sig") as fh:
            m = json.load(fh)
    except (OSError, ValueError):
        return None
    perms = [p for p in m.get("permissions", []) if isinstance(p, str)]
    # MV2 mixes host patterns into permissions; split them out.
    hosts = list(m.get("host_permissions", [])) + [p for p in perms if "/" in p or p == "<all_urls>"]
    perms = [p for p in perms if "/" not in p and p != "<all_urls>"]
    perms += [p for p in m.get("optional_permissions", []) if isinstance(p, str) and "/" not in p]
    matches = []
    for cs in m.get("content_scripts", []) or []:
        matches += cs.get("matches", [])
    return Extension(
        browser=browser,
        profile=profile,
        ext_id=ext_id,
        name=_resolve_msg(m.get("name", "?"), vdir, m.get("default_locale")),
        version=m.get("version", "?"),
        path=vdir,
        permissions=sorted(set(perms)),
        hosts=sorted(set(hosts)),
        content_matches=sorted(set(matches)),
        update_url=m.get("update_url", ""),
    )


def chromium_extensions(browsers=None):
    browsers = browsers if browsers is not None else known.CHROMIUM_BROWSERS
    out = []
    for browser, root in browsers.items():
        if not os.path.isdir(root):
            continue
        # Opera keeps Extensions directly under the root; the rest use per-profile dirs.
        candidates = [("Default", root)] if os.path.isdir(os.path.join(root, "Extensions")) else []
        for d in os.listdir(root):
            p = os.path.join(root, d)
            if os.path.isdir(os.path.join(p, "Extensions")):
                candidates.append((d, p))
        for profile, pdir in candidates:
            ext_dir = os.path.join(pdir, "Extensions")
            for ext_id in os.listdir(ext_dir):
                if ext_id == "Temp":
                    continue
                e = read_chromium_extension(browser, profile, ext_id, os.path.join(ext_dir, ext_id))
                if e:
                    out.append(e)
    return out


def firefox_extensions(profiles_root=None):
    profiles_root = profiles_root or known.FIREFOX_PROFILES
    out = []
    if not os.path.isdir(profiles_root):
        return out
    for prof in os.listdir(profiles_root):
        f = os.path.join(profiles_root, prof, "extensions.json")
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        for a in data.get("addons", []):
            if (a.get("location") or "").startswith(("app-builtin", "app-system")):
                continue  # ships with Firefox itself
            perms = a.get("userPermissions") or {}
            out.append(Extension(
                browser="Firefox",
                profile=prof,
                ext_id=a.get("id", "?"),
                name=(a.get("defaultLocale") or {}).get("name", a.get("id", "?")),
                version=a.get("version", "?"),
                path=a.get("path", ""),
                permissions=sorted(set(perms.get("permissions", []))),
                hosts=sorted(set(perms.get("origins", []))),
                update_url=a.get("sourceURI") or "",
            ))
    return out


def all_extensions():
    return chromium_extensions() + firefox_extensions()


def runs_on_all_sites(ext):
    patterns = ext.hosts + ext.content_matches
    return any(p in known.ALL_SITES for p in patterns)


def from_store(ext):
    if ext.browser == "Firefox":
        return "mozilla.org" in ext.update_url
    return any(u in ext.update_url for u in known.STORE_UPDATE_URLS)


def looks_like_fake_wallet(ext):
    if ext.is_wallet:
        return False
    name = ext.name.lower()
    return any(w in name for w in known.WALLET_NAME_WORDS)


def assess(ext, profile_has_wallet):
    """Return (severity, reasons) for one extension. severity None means nothing notable."""
    reasons = []
    if ext.is_wallet:
        return None, reasons
    if looks_like_fake_wallet(ext):
        reasons.append("name looks like a crypto wallet/tool but it is not a known genuine wallet ID — possible fake")
    if not from_store(ext) and ext.browser != "Firefox":
        reasons.append("not installed from an official web store (sideloaded or developer mode)")
    all_sites = runs_on_all_sites(ext)
    if all_sites and ext.content_matches and any(p in known.ALL_SITES for p in ext.content_matches):
        reasons.append("injects its own code into every website, including crypto sites where you sign transactions")
    elif all_sites:
        reasons.append("can read and change data on all websites")
    for p in ext.permissions:
        if p in known.RISKY_PERMISSIONS:
            reasons.append(f"'{p}' — {known.RISKY_PERMISSIONS[p]}")
    if not reasons:
        return None, reasons

    fake = looks_like_fake_wallet(ext)
    injects = any(p in known.ALL_SITES for p in ext.content_matches)
    if fake and (all_sites or not from_store(ext)):
        sev = "critical"
    elif profile_has_wallet and (injects or "management" in ext.permissions or "debugger" in ext.permissions):
        sev = "high"
    elif profile_has_wallet and (all_sites or any(p in known.RISKY_PERMISSIONS for p in ext.permissions)):
        sev = "medium"
    elif fake or not from_store(ext):
        sev = "medium"
    else:
        sev = "low"
    return sev, reasons


def scan_extensions(exts=None):
    exts = exts if exts is not None else all_extensions()
    findings = []
    by_profile = {}
    for e in exts:
        by_profile.setdefault((e.browser, e.profile), []).append(e)
    for (browser, profile), items in sorted(by_profile.items()):
        wallets = [e for e in items if e.is_wallet]
        if wallets:
            findings.append(Finding(
                "info", "wallet", f"{browser} '{profile}' holds wallet extension(s)",
                ", ".join(f"{e.name} v{e.version}" for e in wallets),
                data={"browser": browser, "profile": profile, "wallets": [e.ext_id for e in wallets]},
            ))
        risky_here = 0
        for e in items:
            sev, reasons = assess(e, bool(wallets))
            if not sev:
                continue
            if wallets and sev in ("high", "medium"):
                risky_here += 1
            findings.append(Finding(
                sev, "extension", f"{browser} '{profile}': {e.name} v{e.version}",
                "; ".join(reasons),
                fix=("Remove it, or move your wallets to a browser profile with no other extensions."
                     if wallets else "Remove it if you don't recognise or need it."),
                data={"id": e.ext_id, "path": e.path, "permissions": e.permissions, "hosts": e.hosts},
            ))
        if wallets and risky_here:
            findings.append(Finding(
                "high", "wallet", f"{browser} '{profile}': wallets share a profile with {risky_here} risky extension(s)",
                "Any extension that runs on every site can swap addresses or alter transactions on dApp pages.",
                fix="Create a separate browser profile used only for crypto, with only the wallet installed.",
            ))
    return findings
