"""WalletGuard command line.

  python -m walletguard scan            one-off security report (read-only)
  python -m walletguard guard           live protection in this console
  python -m walletguard tray            live protection as a tray icon
  python -m walletguard install         start the tray icon at every logon (and now)
  python -m walletguard uninstall       stop starting at logon
  python -m walletguard update-feeds    refresh scam-address / phishing-domain lists
  python -m walletguard check-tx | check-signature | check-origin | check-browser-args
                                        offline checks of things you paste in
"""

import argparse
import datetime
import json
import os
import sys
import threading

from . import __version__, feeds, scanner, watcher
from .alerts import DATA_DIR, LOG_PATH

COLORS = {"critical": "\033[1;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"


def cmd_scan(args):
    print(f"WalletGuard {__version__} — scanning (read-only)…\n", flush=True)
    findings = scanner.full_scan()
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=1))
        return 0
    for f in findings:
        if f.severity == "info" and not args.verbose:
            continue
        c = COLORS.get(f.severity, "") if sys.stdout.isatty() else ""
        print(f"{c}[{f.severity.upper():8}]{RESET if c else ''} {f.title}")
        if f.detail:
            print(f"           {f.detail}")
        if f.fix:
            print(f"           → {f.fix}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in COLORS}
    print("\nSummary: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n))
    os.makedirs(DATA_DIR, exist_ok=True)
    out = os.path.join(DATA_DIR, f"scan-{datetime.datetime.now():%Y%m%d-%H%M%S}.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=1)
    print(f"Full report: {out}")
    return 2 if counts["critical"] or counts["high"] else 0


def cmd_update_feeds(args):
    for name, st in feeds.update(force=args.force).items():
        print(f"{name}: {st}")
    intel = feeds.ThreatIntel.load()
    print(f"Loaded {len(intel.addresses)} scam addresses, {len(intel.domains)} phishing domains.")
    return 0


def cmd_guard(args):
    from .clipboard import ClipboardGuard
    if not args.offline:
        feeds.update()
    intel = feeds.ThreatIntel.load()
    print(f"WalletGuard {__version__} — live protection on.")
    print(f"  Clipboard guard: on{' (will terminate clippers)' if args.kill else ''}")
    print(f"  Threat intel: {len(intel.addresses)} scam addresses, {len(intel.domains)} phishing domains")
    print(f"  Extension watcher: every {args.interval}s")
    print(f"  Event log: {LOG_PATH}\nPress Ctrl+C to stop.\n", flush=True)
    stop = threading.Event()
    threading.Thread(target=watcher.run, args=(args.interval, stop), daemon=True).start()
    try:
        ClipboardGuard(intel if intel.loaded else None, kill=args.kill).run(stop)
    except KeyboardInterrupt:
        stop.set()
        print("Stopped.")
    return 0


def cmd_tray(args):
    from . import tray
    return tray.main(kill=args.kill, interval=args.interval, offline=args.offline)


def cmd_install(args):
    from . import autostart
    if autostart.inside_app_container():
        print("Not installing: this was started from inside another app's sandbox (e.g. an AI agent), so\n"
              "Windows would redirect the logon entry and reports into that app's private storage.\n"
              "Run this command from your own PowerShell or Command Prompt instead.", file=sys.stderr)
        return 1
    print("Starts at logon with:", autostart.install(kill=args.kill))
    if not args.no_start:
        autostart.start_now(kill=args.kill)
        print("Tray icon started — look for the shield in the notification area.")
    return 0


def cmd_uninstall(args):
    from . import autostart
    print("Removed from logon." if autostart.uninstall() else "Was not set to start at logon.")
    print("If the tray icon is running, right-click it → Exit WalletGuard.")
    return 0


def cmd_check(args):
    """Offline checkers for a transaction, signature method, site or browser command line.
    They inspect only what you pass in; output is a list of warnings, never a safety verdict."""
    from .security.browser_launch import analyze_arguments
    from .security.origins import analyze_origin
    from .security.transaction import analyze_sign_method, analyze_transaction
    try:
        if args.cmd == "check-tx":
            findings = analyze_transaction(to=args.to, data=args.data, value_wei=args.value_wei)
        elif args.cmd == "check-signature":
            findings = analyze_sign_method(args.method)
        elif args.cmd == "check-origin":
            findings = analyze_origin(args.url)
        else:
            findings = analyze_arguments(args.args)
    except (TypeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "prototype_not_a_safety_verdict",
                      "findings": [f.to_dict() for f in findings]}, indent=2))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="walletguard", description="Detect and block attacks on crypto wallets.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="one-off read-only security report")
    s.add_argument("--json", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true", help="also show info items")
    s.set_defaults(func=cmd_scan)
    g = sub.add_parser("guard", help="live clipboard guard + extension watcher")
    g.add_argument("--kill", action="store_true", help="terminate the program caught swapping addresses")
    g.add_argument("--interval", type=int, default=60, help="extension check interval, seconds")
    g.add_argument("--offline", action="store_true", help="don't download threat feeds")
    g.set_defaults(func=cmd_guard)
    t = sub.add_parser("tray", help="live protection as a tray icon")
    t.add_argument("--kill", action="store_true")
    t.add_argument("--interval", type=int, default=60)
    t.add_argument("--offline", action="store_true")
    t.set_defaults(func=cmd_tray)
    i = sub.add_parser("install", help="start the tray icon automatically at logon")
    i.add_argument("--kill", action="store_true", help="terminate programs caught swapping addresses")
    i.add_argument("--no-start", action="store_true", help="don't launch it right now")
    i.set_defaults(func=cmd_install)
    sub.add_parser("uninstall", help="stop starting at logon").set_defaults(func=cmd_uninstall)
    c = sub.add_parser("check-tx", help="offline review of an EVM transaction request (no RPC)")
    c.add_argument("--to", help="destination address; omit for contract deployment")
    c.add_argument("--data", default="0x", help="0x-prefixed calldata")
    c.add_argument("--value-wei", type=int, default=0)
    c.set_defaults(func=cmd_check)
    c = sub.add_parser("check-signature", help="offline review of a signing method name")
    c.add_argument("--method", required=True)
    c.set_defaults(func=cmd_check)
    c = sub.add_parser("check-origin", help="offline review of a site URL (never contacts it)")
    c.add_argument("--url", required=True)
    c.set_defaults(func=cmd_check)
    c = sub.add_parser("check-browser-args", help="review browser command-line arguments")
    c.add_argument("args", nargs="*")
    c.set_defaults(func=cmd_check)
    u = sub.add_parser("update-feeds", help="download scam address / phishing domain lists")
    u.add_argument("--force", action="store_true")
    u.set_defaults(func=cmd_update_feeds)
    args = p.parse_args(argv)
    if os.name == "nt":
        os.system("")  # enable ANSI colours in the Windows console
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
