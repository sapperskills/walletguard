"""Windowless launcher for the WalletGuard tray app (run with pythonw.exe)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from walletguard.tray import main  # noqa: E402

sys.exit(main(kill="--kill" in sys.argv[1:], offline="--offline" in sys.argv[1:]))
