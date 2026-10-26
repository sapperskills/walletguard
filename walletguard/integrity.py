"""Wallet extension integrity: catch wallet code that was changed on disk.

Two independent checks:
  1. Store hashes: Chrome-store extensions ship `_metadata/verified_contents.json`, a list
     of tree hashes for every file as published. We recompute them for code files. A
     mismatch, or a code file the store never shipped, means the wallet was patched locally.
     (We don't verify the store's signature, so a careful attacker could rewrite that file
     too; check 2 covers that from the moment a baseline exists.)
  2. Baseline: SHA-256 of every file per wallet version, saved locally. Files that change,
     appear or vanish while the version stays the same mean tampering.
"""

import base64
import hashlib
import json
import os

from . import extensions as ext_mod
from .alerts import DATA_DIR
from .findings import Finding

BASELINE = os.path.join(DATA_DIR, "integrity_baseline.json")

CODE_EXTS = {".js", ".mjs", ".cjs", ".html", ".htm", ".css", ".wasm", ".json"}
# The browser rewrites these when installing, so their store hashes never match.
SKIP_PREFIXES = ("_metadata/", "_locales/")
SKIP_FILES = {"manifest.json"}


def _b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def tree_hash(path, block_size=4096):
    """Chromium's content-verification tree hash: SHA-256 per block, then 128-way branches."""
    leaves = []
    with open(path, "rb") as fh:
        while True:
            b = fh.read(block_size)
            if b or not leaves:
                leaves.append(hashlib.sha256(b).digest())
            if len(b) < block_size:
                break
    branch = block_size // 32
    while len(leaves) > 1:
        leaves = [hashlib.sha256(b"".join(leaves[i:i + branch])).digest() for i in range(0, len(leaves), branch)]
    return leaves[0]


def is_code(rel):
    rel = rel.lower()
    return (os.path.splitext(rel)[1] in CODE_EXTS and rel not in SKIP_FILES
            and not rel.startswith(SKIP_PREFIXES))


def walk_files(vdir):
    out = []
    for root, _, files in os.walk(vdir):
        for f in files:
            out.append(os.path.relpath(os.path.join(root, f), vdir).replace(os.sep, "/"))
    return out


def store_hashes(vdir):
    """{lowercase relpath: (root_hash bytes, block_size)} from verified_contents.json, or None."""
    try:
        with open(os.path.join(vdir, "_metadata", "verified_contents.json"), encoding="utf-8") as fh:
            vc = json.load(fh)
        signed = next(x for x in vc if x.get("description") == "treehash per file")["signed_content"]
        payload = json.loads(_b64u(signed["payload"]))
    except (OSError, ValueError, KeyError, StopIteration, TypeError):
        return None
    out = {}
    for ch in payload.get("content_hashes", []):
        if ch.get("format") != "treehash":
            continue
        for f in ch.get("files", []):
            out[f["path"].lower()] = (_b64u(f["root_hash"]), ch.get("block_size", 4096))
    return out


def verify_against_store(vdir):
    """Return {'status': 'no_metadata'|'ok'|'tampered', 'mismatched': [...], 'extra': [...], 'missing': [...]}."""
    hashes = store_hashes(vdir)
    if hashes is None:
        return {"status": "no_metadata", "mismatched": [], "extra": [], "missing": []}
    on_disk = {r.lower(): r for r in walk_files(vdir)}
    mismatched, missing = [], []
    for rel, (want, block) in hashes.items():
        if not is_code(rel):
            continue
        if rel not in on_disk:
            missing.append(rel)
        elif tree_hash(os.path.join(vdir, on_disk[rel]), block) != want:
            mismatched.append(on_disk[rel])
    extra = sorted(r for low, r in on_disk.items() if is_code(low) and low not in hashes)
    status = "tampered" if mismatched or extra else "ok"
    return {"status": status, "mismatched": sorted(mismatched), "extra": extra, "missing": sorted(missing)}


def file_hashes(path):
    """{relpath: sha256 hex} for a version folder, or {'<file>': hash} for a single file (Firefox .xpi)."""
    if os.path.isfile(path):
        with open(path, "rb") as fh:
            return {os.path.basename(path): hashlib.sha256(fh.read()).hexdigest()}
    out = {}
    for rel in walk_files(path):
        if rel.lower() == "_metadata/computed_hashes.json":
            continue  # the browser rewrites this cache itself
        with open(os.path.join(path, rel), "rb") as fh:
            out[rel] = hashlib.sha256(fh.read()).hexdigest()
    return out


def diff_hashes(old, new):
    changed = sorted(k for k in old.keys() & new.keys() if old[k] != new[k])
    return changed, sorted(new.keys() - old.keys()), sorted(old.keys() - new.keys())


def load_baseline():
    try:
        with open(BASELINE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_baseline(b):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = BASELINE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(b, fh)
    os.replace(tmp, BASELINE)


def _short(files, n=5):
    return ", ".join(files[:n]) + (f" (+{len(files) - n} more)" if len(files) > n else "")


def check_wallets(exts=None, baseline=None):
    """Return (findings, new_baseline). Pure apart from reading the extension files."""
    exts = exts if exts is not None else ext_mod.all_extensions()
    baseline = dict(baseline if baseline is not None else load_baseline())
    findings = []
    for e in exts:
        if not e.is_wallet or not e.path or not os.path.exists(e.path):
            continue
        where = f"{e.browser} '{e.profile}': {e.name} v{e.version}"
        if os.path.isdir(e.path):
            v = verify_against_store(e.path)
            if v["status"] == "tampered":
                findings.append(Finding(
                    "critical", "integrity", f"{where} — wallet code differs from the store's",
                    ("Changed: " + _short(v["mismatched"]) + ". " if v["mismatched"] else "")
                    + ("Files the store never shipped: " + _short(v["extra"]) + ". " if v["extra"] else "")
                    + "Malware patches wallet extensions this way to steal your password and seed phrase.",
                    fix="Do NOT unlock this wallet on this PC. From a clean device, move funds to a NEW wallet "
                        "(new seed phrase). Then remove the extension and run a Defender Offline scan.",
                    data={"path": e.path, **v}))
            elif v["status"] == "no_metadata" and e.browser != "Firefox":
                findings.append(Finding(
                    "medium", "integrity", f"{where} — no store signature data to check against",
                    "This copy has no _metadata/verified_contents.json, so its code can't be compared with the "
                    "store's. Edge Add-ons installs can lack it; a copy loaded from a folder always does.",
                    fix="Make sure the wallet was installed from the official store.", data={"path": e.path}))

        new = file_hashes(e.path)
        old = baseline.get(e.key)
        if old and old.get("version") == e.version:
            changed, added, removed = diff_hashes(old["files"], new)
            if changed or added or removed:
                code_hit = any(is_code(f.lower()) for f in changed + added)
                findings.append(Finding(
                    "critical" if code_hit else "high", "integrity",
                    f"{where} — files changed without an update",
                    ("Changed: " + _short(changed) + ". " if changed else "")
                    + ("New: " + _short(added) + ". " if added else "")
                    + ("Removed: " + _short(removed) + ". " if removed else "")
                    + "The version number is the same, so this was not a normal update.",
                    fix="Do NOT unlock this wallet on this PC until you know why. If you didn't change it, "
                        "treat the PC as infected and move funds to a NEW wallet from a clean device.",
                    data={"path": e.path, "changed": changed, "added": added, "removed": removed}))
                continue  # keep the trusted baseline; don't learn the tampered files
        baseline[e.key] = {"version": e.version, "files": new}
    return findings, baseline


def scan_integrity(update_baseline=True):
    findings, b = check_wallets()
    if update_baseline:
        save_baseline(b)
    return findings
