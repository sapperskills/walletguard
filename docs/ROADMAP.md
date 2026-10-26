# Roadmap

Goal: the best free, local-only protection for the crypto wallets people already use on Windows.
Each item ships with unit tests, a severity rationale and known false positives. See
[GPT_PROMPT.md](GPT_PROMPT.md) for the detailed feature brief.

## Done

- Read-only scanner: Defender, startup items, scheduled tasks, unsigned AppData processes, browser
  extensions (fake wallets, risky permissions, wallets sharing a profile), browser launch tampering
- Clipboard guard: undoes address swaps, warns on look-alike and known-scam addresses and phishing links
- Extension watcher: new installs, permissions gained through updates, changed update sources
- Tray app that starts at logon; threat feeds refreshed every 6 hours
- Offline checkers for transactions (token/NFT approvals), signing methods, site origins
- Force-installed, registry-installed, unpacked and command-line extensions; developer mode
- Wallet extension integrity against the store's published hashes and a local baseline

## Next

1. **Store signature check:** verify the RSA signature on `verified_contents.json` so a stealer can't
   rewrite the store hashes before the first baseline
2. **Live persistence watcher:** alert within a minute on new Run entries, startup files, scheduled tasks,
   services, WMI subscriptions, IFEO debuggers and Winlogon changes
4. **Wallet-file access monitor (admin, opt-in):** audit wallet extension storage and desktop wallet
   folders; alert when a non-browser process reads them (Security event 4663)
5. **Network trust tampering:** hosts entries for wallet/exchange domains, proxies, DNS changes,
   non-Microsoft root certificates
6. **Remote-access scam tools:** AnyDesk, TeamViewer, ScreenConnect, RustDesk etc., and RDP, raised to
   high while a wallet is open
7. **Fake desktop wallets:** check the code-signing publisher of Exodus, Electrum, Ledger Live, Trezor
   Suite and others
8. **Seed-phrase exposure scan (opt-in, local):** find files and screenshots that look like they hold a
   recovery phrase or private key; report the path only
9. **Clipboard guard upgrades:** event-driven listener, a trusted-address book from the tray
10. **Hardening helper (opt-in, reversible):** Controlled Folder Access, Defender ASR rules, SmartScreen
11. **Token approval audit (opt-in, read-only):** list unlimited approvals for addresses you enter

## Not planned

A wallet, key storage or transaction signing of any kind; uploading user data; ads, accounts or payments.
