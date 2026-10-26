# WalletGuard

Detects and blocks attacks on crypto wallets on Windows. Pure Python standard library, no installs needed.
Free, local-only, no telemetry. MIT licensed.

> **Status: early prototype.** It reduces risk; it cannot make a compromised PC safe, and no output is a
> guarantee that a transaction, site or PC is safe. WalletGuard never asks for, reads or stores seed phrases,
> private keys or passwords. See [SECURITY.md](SECURITY.md).

```
python -m walletguard scan            # read-only security report (exit code 2 if anything high/critical)
python -m walletguard guard           # live protection: clipboard guard + extension watcher
python -m walletguard guard --kill    # ...and terminate any program caught swapping addresses
python -m walletguard update-feeds    # refresh scam-address / phishing-domain lists
python -m walletguard install         # run as a tray icon at every logon (and start it now)
python -m walletguard uninstall       # stop starting at logon

# offline checks of things you paste in (no network, no RPC):
python -m walletguard check-tx --to 0x… --data 0x095ea7b3…   # token approvals, NFT approve-all, deployments
python -m walletguard check-signature --method eth_sign
python -m walletguard check-origin --url https://example.org
python -m walletguard check-browser-args -- --remote-debugging-port=9222
```

## Tray icon

`install` adds a `WalletGuard` value to `HKCU\...\CurrentVersion\Run` that launches `WalletGuard.pyw`
with `pythonw.exe` (no console window). Only one copy runs at a time. Right-click the shield for:
pause/resume the clipboard guard, run a scan (opens the report if anything is high-risk), update threat
feeds, open the event log or reports folder, and exit. Warnings appear as tray notifications; a blocked
clipboard hijack also gets a top-most pop-up. Threat feeds refresh every 6 hours.

## What it does

**Scanner** (`scan`)
- Microsoft Defender: real-time/behaviour/tamper protection, definition age, past detections, ransomware protection
- Startup items, startup-folder shortcuts (resolved to their target) and non-Microsoft scheduled tasks:
  encoded PowerShell, hidden script launchers, unsigned or user-folder executables, dead entries
- Unsigned programs running from AppData/Temp, and whether they're connected to the internet
- Every Chrome / Edge / Brave / Vivaldi / Opera / Firefox extension in every profile:
  fake wallets (wallet-like name, unknown ID), sideloaded installs, code injected into every site,
  dangerous permissions (`management`, `proxy`, `cookies`, `debugger`, clipboard…), and wallets
  sharing a profile with risky extensions
- Browser launch tampering: Desktop, Start Menu, taskbar and Run entries that start a browser with
  `--load-extension`, `--remote-debugging-port` and similar flags (tokenised with `CommandLineToArgvW`)
- Desktop wallet data folders (Exodus, Electrum, Atomic, …)

**Offline checkers** (`walletguard/security/`, `check-*` commands)
- EVM transactions: unlimited and limited ERC-20 `approve`, NFT `setApprovalForAll`, native value,
  contract deployment, and anything it can't decode is flagged rather than assumed safe
- Signing methods (`eth_sign`, typed data), site origins (plain HTTP, credentials in the URL, punycode),
  browser argument lists

**Clipboard guard** (`guard`)
- Recognises EVM, BTC, LTC, TRON, DOGE, XMR, XRP and Solana addresses
- If a copied address is replaced by a different one of the same chain within 1.5 s, it is a clipper:
  the original is put back, the program that wrote the clipboard is named (and killed with `--kill`), and you get a pop-up
- Look-alike addresses (same first/last 4 characters, the address-poisoning trick) → warning
- Copied addresses on the ScamSniffer scam list, or links to known phishing domains → warning

**Extension watcher** (`guard`)
- Baseline of all extensions; alerts on new installs (especially next to a wallet), extensions that
  gain permissions through an update, changed update sources, and wallets that disappear

Data, baselines, scan reports and the event log live in `%LOCALAPPDATA%\WalletGuard`.

## Threat feeds

Downloaded at runtime, cached for 24 h, never copied into this repo:
- [ScamSniffer scam-database](https://github.com/scamsniffer/scam-database) (GPL-3.0 data)
- [MetaMask eth-phishing-detect](https://github.com/MetaMask/eth-phishing-detect) (DBAD licence)

## Tests

```
python -m unittest discover -s tests -v
```

## Roadmap

Near term (device protection):
- Wallet extension integrity: alert when wallet extension files change without a version change
- Force-installed extension policies (`ExtensionInstallForcelist`) and developer-mode extensions
- Wallet-file access monitor: Windows object-access auditing (event 4663) on wallet extension storage
  and desktop wallet folders, alert when a non-browser process reads them (needs admin, opt-in)
- Live persistence watcher: alert the moment a new startup item or scheduled task appears
- Hosts/proxy/DNS/root-certificate tampering, remote-access scam tools

Full list in [docs/ROADMAP.md](docs/ROADMAP.md); [docs/GPT_PROMPT.md](docs/GPT_PROMPT.md) is the
detailed feature brief. WalletGuard protects the wallets you already use; it will never be a wallet itself.
