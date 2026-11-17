"""Harmless Optimizely-style attack-surface characterization.

These tests describe CURRENT behavior and must not be interpreted as proof of
protection. They use only synthetic EVM addresses and no real wallet/requests.
Run on Windows; clipboard.py imports Win32 APIs at import time.
"""
import unittest

from walletguard.clipboard import ClipboardPolicy
from walletguard.security.origins import analyze_origin
from walletguard.security.transaction import analyze_transaction

A = "0x" + "11" * 20
B = "0x" + "22" * 20


class CompromisedPageThreatModel(unittest.TestCase):
    def test_clipboard_clipper_swap_is_restored_when_both_values_observed(self):
        policy = ClipboardPolicy()
        self.assertEqual(policy.observe(A, 100.0).action, "ok")
        verdict = policy.observe(B, 100.25)
        self.assertEqual(verdict.action, "restore")
        self.assertEqual(verdict.original, A)

    def test_compromised_page_can_pre_poison_first_copied_address(self):
        # The attacker destination is already shown on the page when copied.
        # The original never reaches WalletGuard. THIS IS A COVERAGE GAP.
        policy = ClipboardPolicy()
        self.assertEqual(policy.observe(B, 100.0).action, "ok")

    def test_wallet_request_change_without_clipboard_is_not_intercepted(self):
        # The transaction checker only inspects fields supplied by its caller.
        # A bare native-value transfer has no trusted-receiver comparison.
        findings = analyze_transaction(to=B, value_wei=1234)
        self.assertTrue(any(f.category == "native-transfer" for f in findings))
        self.assertFalse(any(f.category == "recipient-mismatch" for f in findings))

    def test_legitimate_https_origin_does_not_detect_injected_script(self):
        findings = analyze_origin("https://example.org/send")
        self.assertTrue(any(f.category == "scope" for f in findings))
        self.assertFalse(any(f.severity in {"high", "critical"} for f in findings))


if __name__ == "__main__":
    unittest.main()
