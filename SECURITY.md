# Security policy and threat model

## Current trust level

Research/development prototype. The Windows scanner, clipboard guard and extension watcher are read-only apart from the opt-in actions listed in README (restoring a hijacked clipboard, `--kill`, the logon Run entry). The wallet parts are design only: **no keys, no signing, no real-money use.**
No statement in a CLI finding proves safety. The `info` severity means the
specified narrow rule did not flag a high-risk pattern, not that an asset is safe.

## Non-negotiable design controls

1. Self-custody, local-only encrypted key vault, no cloud backup or recovery service.
2. Use reviewed standard crypto and platform secure key management. Never write your
   own ECDSA, Keccak, KDF, RNG, BIP32 or BIP39 implementations.
3. Secrets never appear in logs, crash reports, telemetry, issue attachments,
   terminal arguments, debug builds, screenshots or AI prompts.
4. Untrusted web pages, browser content scripts, dApp providers, RPC replies and
   AI assistants **cannot access seed/key material or authorize a signature**.
5. Signing requires explicit, foreground user authorization. Display exact chain,
   verifying contract, recipient, asset effect and approval scope on a trusted UI.
   Clear domain separation for typed-data signatures and replay protection.
6. No silently auto-signing, delegated approvals, background transfers or externally
   reachable native debug endpoints. Owner must be able to revoke permissions.
7. Browser extension requests minimal permissions. Native messaging requires exact
   allowlisted extension ID and authenticated, narrow commands. Separate OS process
   for system monitoring; never grant admin privilege to the signing service.
8. Fail closed on errors in transaction interpretation. Simulations are informative
   but may be incomplete, time-sensitive or manipulated by untrusted RPCs.
9. No telemetry, cloud dependency, ads or mandatory centralized services.
   User-controlled RPC endpoints should be configurable, with privacy disclosures.
10. No production funds before threat modeling, secure code review, independent
    audit, fuzz testing, reproducible-build assessment and incident-response plan.

## High-priority threats

- Malicious dApps and signatures, fake token approvals, deceptive UI, contract
  proxies, nested multicalls and wallet-draining smart contracts.
- Compromised browser extension, background page or content script; malicious
  extension updates; provider injection and phishing origin spoofing.
- Infostealers, clipboard clippers, keyboard and screen malware, malicious
  native applications, privileged OS compromise, and hostile remote-control tools.
- Malicious or compromised blockchain RPC endpoints giving deceptive state or
  transaction simulations. Chain switch, network ID confusion and replay.
- Misleading backup prompts, exported seed/keystore exposures, lost devices,
  device theft, and supply-chain compromise in builds and updates.

## Explicit boundaries

A wallet application cannot guarantee defense from an already fully compromised
operating system. Windows admin and Android accessibility abuse may bypass app
security. Never describe Windows antivirus integration as total protection.
Offline signing is possible when supported but transaction broadcasting is online.

## Safe testing

- Use local synthetic addresses, testnets and generated nonsensitive dummy payloads.
- Do not open a real wallet, import live seeds, or execute a real drainer transaction.
- Verify every test fails before and passes after a security fix.
- Check `python -m unittest discover -s tests` after each change.

## Vulnerability reporting

Do not open public issues containing exploitable details or wallet secrets.
Until a private advisory channel is established, coordinate a private disclosure
route with the repository owner. Never request users' seed phrases for debugging.

