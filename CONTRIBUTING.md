# Contributing to WalletGuard

Thanks for helping protect people's crypto. WalletGuard is free, local-only and open source (MIT).

## Ground rules (non-negotiable)

1. **Never touch secrets.** No code may ask for, read, store, log or send seed phrases, private keys,
   wallet vaults, passwords or tokens. Detectors report paths and types, never the secret.
2. **No telemetry, no accounts, no uploads.** The only network traffic is downloading public threat feeds.
3. **Standard library only.** No third-party packages. Propose one in an issue first if you think it's essential.
4. **Read-only by default.** Anything that changes the system (killing processes, registry, audit policy,
   firewall) must be opt-in, reversible and logged, and must never touch browsers, Explorer or Windows itself.
5. **Original code only.** Don't paste code from GPL/AGPL, unlicensed or custom-licensed projects
   (including MetaMask's repos). Downloading public data at runtime is fine; vendoring it is not.
6. **No real malware, seeds or funds in tests.** Simulate attacks harmlessly (fake extension folders,
   synthetic addresses built with the format's own checksum, test shortcuts).
7. **Never word output as a guarantee.** WalletGuard lowers risk; it can't prove a PC or transaction is safe.

## Getting started

```
git clone https://github.com/sapperskills/walletguard
cd walletguard
python -m unittest discover -s tests -v     # Python 3.10+ on Windows
python -m walletguard scan                  # read-only report
```

Run it from your own terminal, not from inside an app sandbox such as an AI agent (see README).

## Making a change

- One focused feature or fix per pull request.
- Keep pure logic separate from Win32 calls (like `ClipboardPolicy` vs `ClipboardGuard`) and unit-test the logic.
- Every new detector needs: a severity rationale, a plain-English `fix`, and its known false positives in the PR.
- New wallet extension IDs must link to the official Chrome Web Store listing in the PR.
- New address formats must validate the format's checksum and include a published test vector where one exists.
- All tests must pass.

Good places to start: issues labelled **good first issue**, and the list in [docs/ROADMAP.md](docs/ROADMAP.md).

## Reporting a security problem

Don't open a public issue with exploit details. Use GitHub's **Report a vulnerability** button on the
Security tab. Never send anyone your seed phrase, including for debugging.
