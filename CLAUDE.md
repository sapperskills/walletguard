# WalletGuard — engineering instructions

Free, local-first protection for crypto wallets on Windows: a scanner, clipboard guard, extension
watcher and tray app, plus offline transaction/site checkers. It protects existing wallets and is
never a wallet itself (docs/ROADMAP.md). Separate from CutShit and Skynet.

Read README.md, SECURITY.md and the source you are changing before editing.
Tests: `python -m unittest discover -s tests`.

## Hard rules

1. Never ask for, read, store, transmit or log seed phrases, private keys, vault contents,
   passwords or tokens. Report paths and types, never secrets.
2. Python standard library only. New dependencies need a licence and security reason, and owner approval.
3. No telemetry. Network use is limited to downloading public threat feeds; anything else is opt-in.
4. Read-only by default. Anything that changes the system (killing processes, registry, audit
   policy, firewall, quarantine) is opt-in, reversible and logged. Never touch browsers, Explorer
   or Windows system processes.
5. Original code only. No code from GPL/AGPL, MetaMask's custom-licensed or unlicensed repos;
   feeds are downloaded at runtime, never vendored.
6. No false-positive storms: the owner's dev tools (`C:\dev`, CutShit, Ollama, Electron dev builds,
   PowerShell tasks) must not rate high unless several indicators agree.
7. Every feature: pure logic separated from Win32 with unit tests, a severity rationale, a plain-English
   `fix`, and known false positives. Never word output as a guarantee of safety.
8. One focused feature per commit/PR. No wallet, key-handling or signing code: that is out of scope.
