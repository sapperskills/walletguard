"""Extension watcher: alert when extensions appear, change permissions, or land next to a wallet."""

import json
import os
import time

from . import extensions as ext_mod
from .alerts import DATA_DIR, alert, log_event

BASELINE = os.path.join(DATA_DIR, "extensions_baseline.json")


def snapshot(exts=None):
    exts = exts if exts is not None else ext_mod.all_extensions()
    return {e.key: {"name": e.name, "version": e.version, "browser": e.browser, "profile": e.profile,
                    "id": e.ext_id, "wallet": e.is_wallet, "permissions": e.permissions,
                    "hosts": e.hosts, "content": e.content_matches, "update_url": e.update_url}
            for e in exts}


def load_baseline():
    try:
        with open(BASELINE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save_baseline(snap):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(BASELINE, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=1)


def diff(old, new, exts_by_key):
    """Return a list of (severity, title, message) describing what changed."""
    events = []
    wallet_profiles = {(v["browser"], v["profile"]) for v in new.values() if v["wallet"]}
    for key, cur in new.items():
        prev = old.get(key)
        e = exts_by_key.get(key)
        has_wallet = (cur["browser"], cur["profile"]) in wallet_profiles
        where = f"{cur['browser']} profile '{cur['profile']}'"
        if prev is None:
            sev, reasons = ext_mod.assess(e, has_wallet) if e else (None, [])
            if cur["wallet"]:
                events.append(("low", "Wallet extension installed", f"{cur['name']} v{cur['version']} in {where}."))
            else:
                events.append((sev or ("medium" if has_wallet else "low"),
                               "New extension installed" + (" next to your wallet" if has_wallet else ""),
                               f"{cur['name']} v{cur['version']} in {where}."
                               + ("\n\n" + "\n".join("• " + r for r in reasons) if reasons else "")))
            continue
        gained_perms = set(cur["permissions"]) - set(prev["permissions"])
        gained_hosts = (set(cur["hosts"]) | set(cur["content"])) - (set(prev["hosts"]) | set(prev["content"]))
        if gained_perms or gained_hosts:
            # Clean extensions turned malicious through an update is a documented 2026 pattern.
            sev = "high" if has_wallet and not cur["wallet"] else "medium"
            msg = f"{cur['name']} updated {prev['version']} → {cur['version']} in {where} and gained new access:"
            msg += "".join(f"\n• permission: {p}" for p in sorted(gained_perms))
            msg += "".join(f"\n• runs on: {h}" for h in sorted(gained_hosts)[:10])
            events.append((sev, "Extension gained new permissions", msg))
        if prev["update_url"] != cur["update_url"]:
            events.append(("high", "Extension update source changed",
                           f"{cur['name']} in {where} now updates from '{cur['update_url'] or 'nowhere (sideloaded)'}'."))
    for key, prev in old.items():
        if key not in new and prev["wallet"]:
            events.append(("medium", "Wallet extension removed",
                           f"{prev['name']} is gone from {prev['browser']} profile '{prev['profile']}'. "
                           "If you didn't remove it, malware may have."))
    return events


def check_once(update_baseline=True):
    exts = ext_mod.all_extensions()
    new = snapshot(exts)
    old = load_baseline()
    if old is None:
        save_baseline(new)
        return []
    events = diff(old, new, {e.key: e for e in exts})
    for sev, title, msg in events:
        log_event("extension_change", severity=sev, title=title, message=msg)
        if sev in ("critical", "high", "medium"):
            alert(title, msg, critical=sev in ("critical", "high"), dedupe_key="ext:" + msg[:80], quiet_seconds=3600)
        else:
            print(f"[i] {title}: {msg}", flush=True)
    if update_baseline:
        save_baseline(new)
    return events


def run(interval=60, stop_event=None):
    while not (stop_event and stop_event.is_set()):
        try:
            check_once()
        except Exception as e:
            log_event("extension_watch_error", error=repr(e))
        if stop_event:
            stop_event.wait(interval)
        else:
            time.sleep(interval)
