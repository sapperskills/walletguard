"""Public threat feeds of scam addresses and phishing domains, cached locally.

The feeds are downloaded at runtime and kept as data; none of their content is
copied into this source tree.
  * ScamSniffer scam-database (GPL-3.0 data): https://github.com/scamsniffer/scam-database
  * MetaMask eth-phishing-detect (DBAD licence): https://github.com/MetaMask/eth-phishing-detect
"""

import json
import os
import time
import urllib.request
from urllib.parse import urlparse

from .alerts import DATA_DIR

FEED_DIR = os.path.join(DATA_DIR, "feeds")
MAX_AGE = 24 * 3600

FEEDS = {
    "scamsniffer_addresses.json":
        "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json",
    "scamsniffer_domains.json":
        "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
    "metamask_config.json":
        "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json",
}


def update(force=False, timeout=30):
    """Download any feed older than a day. Returns {name: 'updated'|'fresh'|error}."""
    os.makedirs(FEED_DIR, exist_ok=True)
    status = {}
    for name, url in FEEDS.items():
        path = os.path.join(FEED_DIR, name)
        if not force and os.path.exists(path) and time.time() - os.path.getmtime(path) < MAX_AGE:
            status[name] = "fresh"
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "WalletGuard"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
            json.loads(raw)  # refuse to cache anything that isn't valid JSON
            tmp = path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(raw)
            os.replace(tmp, path)
            status[name] = "updated"
        except Exception as e:
            status[name] = f"failed: {e}"
    return status


def _load(name):
    try:
        with open(os.path.join(FEED_DIR, name), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _strings(obj):
    """Flatten whatever list/dict shape a feed uses into a set of strings."""
    out = set()
    if isinstance(obj, str):
        out.add(obj)
    elif isinstance(obj, list):
        for x in obj:
            out |= _strings(x)
    elif isinstance(obj, dict):
        for v in obj.values():
            out |= _strings(v)
    return out


class ThreatIntel:
    def __init__(self, addresses=None, domains=None, allow_domains=None):
        self.addresses = {a.lower() for a in (addresses or ())}
        self.domains = {d.lower() for d in (domains or ())}
        self.allow_domains = {d.lower() for d in (allow_domains or ())}

    @classmethod
    def load(cls):
        addrs = _strings(_load("scamsniffer_addresses.json"))
        doms = _strings(_load("scamsniffer_domains.json"))
        allow = set()
        mm = _load("metamask_config.json")
        if isinstance(mm, dict):
            doms |= set(mm.get("blacklist", []))
            allow |= set(mm.get("whitelist", []))
        return cls(addrs, doms, allow)

    @property
    def loaded(self):
        return bool(self.addresses or self.domains)

    def bad_address(self, addr):
        return addr.strip().lower() in self.addresses

    def bad_domain(self, text):
        t = text.strip()
        if " " in t or len(t) > 2048:
            return None
        host = urlparse(t if "://" in t else "http://" + t).hostname or ""
        host = host.lower().rstrip(".")
        if not host or "." not in host:
            return None
        parts = host.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in self.allow_domains:
                return None
            if cand in self.domains:
                return cand
        return None
