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

> Run `install` (or start `WalletGuard.pyw`) from your own terminal or Explorer, not from inside another
> app such as an AI coding agent. Windows redirects a packaged app's AppData and registry writes into its
> private storage, so reports and the logon entry would be invisible to Notepad and to Windows at logon.
> `install` refuses to run in that situation.

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
- Knows the official IDs of 58 wallet extensions (MetaMask, Phantom, Solflare, Rabby, Keplr, Leap, Petra,
  Slush, Tonkeeper, Lace, Eternl, Talisman, SubWallet, Braavos, Argent, Freighter, Bitget, Zerion, …), each
  checked against its Chrome Web Store listing, so a copy with a different ID is spotted as a possible fake
- Every Chrome / Edge / Brave / Vivaldi / Opera / Firefox extension in every profile:
  fake wallets (wallet-like name, unknown ID), sideloaded installs, code injected into every site,
  dangerous permissions (`management`, `proxy`, `cookies`, `debugger`, clipboard…), and wallets
  sharing a profile with risky extensions
- Browser launch tampering: Desktop, Start Menu, taskbar and Run entries that start a browser with
  `--load-extension`, `--remote-debugging-port` and similar flags (tokenised with `CommandLineToArgvW`)
- Extensions you didn't install yourself: forced by browser policy (`ExtensionInstallForcelist`,
  `ExtensionSettings`, Firefox `policies.json`), registered by other software, loaded unpacked or from the
  command line (critical if it reuses a real wallet's ID), and developer mode left on
- **Wallet integrity:** each wallet extension's code is checked against the hashes the Chrome Web Store
  published (`_metadata/verified_contents.json`), and against a local baseline, so code patched on disk,
  injected scripts, or files changed without a version change are caught. Re-checked every 10 minutes by `guard`/tray
- Desktop wallet data folders (Exodus, Electrum, Atomic, …)

**Offline checkers** (`walletguard/security/`, `check-*` commands)
- EVM transactions: unlimited and limited ERC-20 `approve`, NFT `setApprovalForAll`, native value,
  contract deployment, and anything it can't decode is flagged rather than assumed safe
- Signing methods (`eth_sign`, typed data), site origins (plain HTTP, credentials in the URL, punycode),
  browser argument lists

**Clipboard guard** (`guard`)
- Recognises addresses on 30+ chains, **validating each format's checksum** so ordinary text and typos are
  never mistaken for an address: Ethereum and every EVM chain (EIP-55), Bitcoin (legacy, P2SH, SegWit,
  Taproot per BIP-173/350), Solana, Tron, Litecoin, Dogecoin, Dash, Zcash, Bitcoin Cash and Kaspa
  (CashAddr), XRP, Stellar, TON, Cardano, Polkadot/Kusama/Substrate (SS58), Algorand, Monero,
  Sui/Aptos/Starknet, every Cosmos SDK chain (Cosmos Hub, Osmosis, Injective, Sei, Celestia, dYdX, …),
  plus `.eth`, `.sol`, `.ton` and `.near` names
- An EVM address whose mixed-case checksum is wrong (mistyped or altered) → warning
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
