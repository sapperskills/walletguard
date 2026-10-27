# Security policy and threat model

## What WalletGuard is

A free, local-only tool that protects the crypto wallets you already use (browser extensions such as
MetaMask/Phantom/Solflare and desktop wallets) on Windows. It is **not a wallet**: it never creates,
imports, holds or signs with keys, and it never asks for a seed phrase or password.

It is an early prototype. It lowers risk; it cannot make an already-compromised PC safe, and no finding,
or lack of findings, is a guarantee that a PC, site or transaction is safe.

## Design rules

1. **Secrets never touched.** No reading, storing, logging or sending seed phrases, private keys, vault
   contents, passwords or tokens. Detectors report paths and types, never the secret itself.
2. **Local only.** No accounts, telemetry or uploads. The only network traffic is downloading public
   threat feeds (ScamSniffer, MetaMask eth-phishing-detect). Any future online lookup is opt-in.
3. **Read-only by default.** The only actions taken without a flag are putting back a hijacked clipboard
   address and showing alerts. Everything else that changes the system (`--kill`, the logon Run entry,
   and any future audit-policy, firewall or quarantine feature) is opt-in, reversible and logged.
4. **Never touch** browsers, Explorer or Windows system processes, even with `--kill`.
5. **Fail loud, not safe.** Anything a checker can't understand is reported as unverified, never as safe.
6. **Low noise.** Every detector has an allowlist story and severity rationale; developer tools are not
   treated as malware on one weak signal.
7. **Standard library only**, original code only; third-party data is downloaded at runtime, never vendored.

## Threats in scope

- Infostealers copying wallet extension storage, desktop wallet files, cookies and saved passwords
- Clipboard clippers and address poisoning
- Malicious, fake or hijacked browser extensions, including clean extensions turned malicious by an update
- Browser launch tampering (`--load-extension`, remote debugging) and force-installed extension policies
- Persistence: startup items, scheduled tasks and similar autostart points
- Phishing and drainer sites, approval phishing (unlimited token approvals, NFT approve-all, `eth_sign`)
- Remote-access scam tools, and hosts/proxy/DNS/root-certificate tampering (planned)

## Limits

An attacker with admin rights can disable or blind any user-mode tool, including this one. WalletGuard is
not an antivirus replacement: keep Microsoft Defender (or another AV) on. A hardware wallet, checking
addresses on its own screen, and keeping your seed phrase offline remain the strongest protections.

## Safe testing

Simulate attacks harmlessly (synthetic addresses, fake extension folders, test shortcuts). Never use real
malware, real seed phrases or real funds in tests. Run `python -m unittest discover -s tests` after every change.

## Reporting a vulnerability

Do not open a public issue with exploit details. Use **Report a vulnerability** on this repository's
Security tab (GitHub private vulnerability reporting). Never send anyone your seed phrase, including for debugging.
