import unittest
from walletguard.security.browser_launch import analyze_arguments
from walletguard.security.origins import analyze_origin


class BrowserPolicyTests(unittest.TestCase):
    def test_remote_debugging_flag(self):
        r = analyze_arguments(["chrome.exe", "--remote-debugging-port=9222"])
        self.assertEqual([f.category for f in r], ["browser-launch"])

    def test_plain_argument_not_mistaken_for_flag(self):
        self.assertEqual(analyze_arguments(["chrome.exe", "C:\\temp\\--load-extension"]), [])

    def test_flag_dedup(self):
        r = analyze_arguments(["--load-extension=A", "--load-extension=B"])
        self.assertEqual(len(r), 1)

    def test_disabled_except(self):
        self.assertEqual(analyze_arguments(["--disable-extensions-except=/example"])[0].severity, "medium")

    def test_no_warning_on_dev_profile(self):
        self.assertEqual(analyze_arguments(["--user-data-dir=C:\\dev\\chrome-test"]), [])

    def test_type_error(self):
        with self.assertRaises(TypeError):
            analyze_arguments([123])

    def test_normal_https(self):
        self.assertEqual(analyze_origin("https://example.org")[0].severity, "info")

    def test_plain_http_high(self):
        self.assertEqual(analyze_origin("http://example.org")[0].severity, "high")

    def test_localhost_http_low(self):
        self.assertEqual(analyze_origin("http://localhost:3000")[0].severity, "low")

    def test_embedded_credentials_high(self):
        self.assertEqual(analyze_origin("https://wallet.example@evil.example")[0].severity, "high")

    def test_punycode_medium(self):
        self.assertEqual(analyze_origin("https://xn--e1afmkfd.example")[0].severity, "medium")

    def test_unsupported_scheme_high(self):
        self.assertEqual(analyze_origin("javascript:alert(1)")[0].severity, "high")

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            analyze_origin("https://example.org:abc")


if __name__ == "__main__":
    unittest.main()
