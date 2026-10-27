import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from walletguard import addresses, extensions, watcher
from walletguard.clipboard import ClipboardPolicy
from walletguard.feeds import ThreatIntel

ETH_A = "0x52908400098527886E0F7030069857D2E4169EE7"
ETH_B = "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
ETH_LOOKALIKE = "0x5290aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9EE7"
BTC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
BTC_LEGACY = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
SOL = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV"
TRON = "TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9"


class Addresses(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(addresses.classify(ETH_A), "EVM")
        self.assertEqual(addresses.classify(f"  {BTC}\n"), "BTC")
        self.assertEqual(addresses.classify(BTC_LEGACY), "BTC")
        self.assertEqual(addresses.classify(SOL), "SOL")
        self.assertEqual(addresses.classify(TRON), "TRON")

    def test_not_addresses(self):
        for t in ("hello world", "", "0x1234", "https://example.com", "abcdefghijkmnopqrstuvwxyzabcdefghijk",
                  f"send to {ETH_A}"):
            self.assertIsNone(addresses.classify(t), t)

    def test_lookalike(self):
        self.assertTrue(addresses.lookalike(ETH_A, ETH_LOOKALIKE))
        self.assertFalse(addresses.lookalike(ETH_A, ETH_B))
        self.assertFalse(addresses.lookalike(ETH_A, ETH_A.lower()))


class Clipboard(unittest.TestCase):
    def test_fast_swap_is_restored(self):
        p = ClipboardPolicy()
        self.assertEqual(p.observe(ETH_A, 100.0).action, "ok")
        v = p.observe(ETH_B, 100.3)
        self.assertEqual(v.action, "restore")
        self.assertEqual(v.original, ETH_A)

    def test_repeat_swap_after_restore_is_caught(self):
        p = ClipboardPolicy()
        p.observe(ETH_A, 100.0)
        self.assertEqual(p.observe(ETH_B, 100.2).action, "restore")
        p.restored(105.0)  # clipper waits, then tries again
        self.assertEqual(p.observe(ETH_B, 105.4).action, "restore")

    def test_human_copy_is_fine(self):
        p = ClipboardPolicy()
        p.observe(ETH_A, 100.0)
        self.assertEqual(p.observe(ETH_B, 110.0).action, "ok")

    def test_different_chain_is_not_a_swap(self):
        p = ClipboardPolicy()
        p.observe(ETH_A, 100.0)
        self.assertEqual(p.observe(BTC, 100.2).action, "ok")

    def test_text_in_between_resets(self):
        p = ClipboardPolicy()
        p.observe(ETH_A, 100.0)
        p.observe("some note", 100.1)
        self.assertEqual(p.observe(ETH_B, 100.2).action, "ok")

    def test_lookalike_warns(self):
        p = ClipboardPolicy()
        p.observe(ETH_A, 100.0)
        self.assertEqual(p.observe(ETH_LOOKALIKE, 200.0).action, "warn")

    def test_scam_address_and_domain(self):
        intel = ThreatIntel(addresses=[ETH_B], domains=["evil-airdrop.xyz"], allow_domains=["metamask.io"])
        p = ClipboardPolicy(intel)
        self.assertEqual(p.observe(ETH_B, 1.0).action, "warn")
        self.assertEqual(p.observe("https://claim.evil-airdrop.xyz/x", 2.0).action, "warn")
        self.assertEqual(p.observe("https://metamask.io", 3.0).action, "ok")


def make_ext(root, ext_id, manifest):
    d = os.path.join(root, ext_id, "1.0.0_0")
    os.makedirs(d)
    with open(os.path.join(d, "manifest.json"), "w") as fh:
        json.dump(manifest, fh)


STORE = "https://clients2.google.com/service/update2/crx"


class Extensions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        ext_dir = os.path.join(self.tmp.name, "Default", "Extensions")
        make_ext(ext_dir, "nkbihfbeogaeaoehlefnkodbefgpgknn", {"name": "MetaMask", "version": "13", "update_url": STORE})
        make_ext(ext_dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", {
            "name": "Video downloader", "version": "1", "update_url": STORE,
            "host_permissions": ["<all_urls>"], "content_scripts": [{"matches": ["<all_urls>"]}]})
        make_ext(ext_dir, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", {
            "name": "MetaMask Wallet Pro", "version": "1", "permissions": ["<all_urls>", "storage"]})
        self.exts = extensions.chromium_extensions({"Chrome": self.tmp.name})

    def tearDown(self):
        self.tmp.cleanup()

    def test_inventory_and_scoring(self):
        by_id = {e.ext_id: e for e in self.exts}
        self.assertTrue(by_id["nkbihfbeogaeaoehlefnkodbefgpgknn"].is_wallet)
        sev, _ = extensions.assess(by_id["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], True)
        self.assertEqual(sev, "high")
        sev, reasons = extensions.assess(by_id["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"], True)
        self.assertEqual(sev, "critical")
        self.assertTrue(any("fake" in r for r in reasons))

    def test_scan_flags_shared_profile(self):
        titles = [f.title for f in extensions.scan_extensions(self.exts)]
        self.assertTrue(any("wallets share a profile" in t for t in titles))

    def test_watcher_detects_new_permission(self):
        old = watcher.snapshot(self.exts)
        e = next(x for x in self.exts if x.ext_id.startswith("a"))
        new = watcher.snapshot(self.exts)
        new[e.key] = dict(new[e.key], permissions=["management"], version="2")
        events = watcher.diff(old, new, {x.key: x for x in self.exts})
        self.assertEqual(events[0][0], "high")
        self.assertIn("management", events[0][2])

    def test_watcher_detects_new_extension_next_to_wallet(self):
        old = watcher.snapshot([x for x in self.exts if not x.ext_id.startswith("b")])
        new = watcher.snapshot(self.exts)
        events = watcher.diff(old, new, {x.key: x for x in self.exts})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "critical")


class TrayReports(unittest.TestCase):
    def test_latest_report_picks_newest_txt(self):
        from walletguard import tray
        with tempfile.TemporaryDirectory() as d:
            for name in ("scan-20261026-100000.txt", "scan-20261026-120000.txt",
                         "scan-20261026-130000.json", "events.log"):
                open(os.path.join(d, name), "w").close()
            old, tray.DATA_DIR = tray.DATA_DIR, d
            try:
                self.assertEqual(os.path.basename(tray.latest_report()), "scan-20261026-120000.txt")
            finally:
                tray.DATA_DIR = old

    def test_no_reports(self):
        from walletguard import tray
        with tempfile.TemporaryDirectory() as d:
            old, tray.DATA_DIR = tray.DATA_DIR, d
            try:
                self.assertIsNone(tray.latest_report())
            finally:
                tray.DATA_DIR = old


class BrowserLaunch(unittest.TestCase):
    def test_windows_tokenising(self):
        from walletguard.system import split_command_line
        self.assertEqual(split_command_line(r'"C:\Program Files\Google\Chrome\chrome.exe" --load-extension="C:\x y"'),
                         [r"C:\Program Files\Google\Chrome\chrome.exe", r"--load-extension=C:\x y"])

    def test_tampered_shortcut_is_high(self):
        from walletguard.system import check_browser_launch
        f = check_browser_launch([(r"C:\Users\u\Desktop\Google Chrome.lnk",
                                   r'"C:\Program Files\Google\Chrome\chrome.exe" --load-extension=C:\Users\u\AppData\x')])
        self.assertEqual([x.severity for x in f], ["high"])

    def test_dev_shortcut_is_medium_and_clean_is_silent(self):
        from walletguard.system import check_browser_launch
        dev = check_browser_launch([(r"C:\dev\tools\chrome-debug.lnk", '"chrome.exe" --remote-debugging-port=9222')])
        self.assertEqual([x.severity for x in dev], ["medium"])
        self.assertEqual(check_browser_launch([("Edge.lnk", '"msedge.exe" --profile-directory=Default')]), [])


if __name__ == "__main__":
    unittest.main()
