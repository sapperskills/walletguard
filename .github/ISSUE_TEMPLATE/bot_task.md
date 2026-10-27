---
name: Bot task (maintainers)
about: A small change wgbot can attempt; a maintainer adds the bot-task label
labels: ''
---

What should change, in one or two sentences:

Files: walletguard/CHANGE_ME.py
Test:
```python
import unittest
from walletguard import addresses


class T(unittest.TestCase):
    def test_behaviour(self):
        # Must FAIL on main today and PASS once fixed.
        self.assertEqual(addresses.classify("..."), "...")
```
