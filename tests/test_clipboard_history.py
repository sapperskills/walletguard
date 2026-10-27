"""Example detector tests (docs/WRITING_A_DETECTOR.md): feed assess() made-up settings, check the findings."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from walletguard import clipboard_history


class ClipboardHistory(unittest.TestCase):
    def test_default_windows_is_quiet(self):
        self.assertEqual(clipboard_history.assess({}), [])

    def test_history_on_is_low(self):
        f = clipboard_history.assess({"EnableClipboardHistory": 1})
        self.assertEqual([x.severity for x in f], ["low"])
        self.assertIn("Win+V", f[0].fix)

    def test_cloud_auto_upload_is_medium(self):
        f = clipboard_history.assess({"EnableClipboardHistory": 1, "EnableCloudClipboard": 1,
                                      "CloudClipboardAutomaticUpload": 1})
        self.assertEqual([x.severity for x in f], ["medium"])

    def test_cloud_manual_sync_is_just_history(self):
        f = clipboard_history.assess({"EnableClipboardHistory": 1, "EnableCloudClipboard": 1,
                                      "CloudClipboardAutomaticUpload": 0})
        self.assertEqual([x.severity for x in f], ["low"])

    def test_collector_runs_on_this_pc(self):
        self.assertIsInstance(clipboard_history.read_settings(), dict)


if __name__ == "__main__":
    unittest.main()
