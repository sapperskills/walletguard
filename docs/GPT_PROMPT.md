You are a senior Windows security engineer extending **WalletGuard**, an open-source tool in `C:\dev\WalletGuard` that detects and blocks attacks on crypto wallets on a Windows 11 PC. The goal is the best personal crypto-protection tool possible: catch real attacks early, block them where it is safe to, and almost never cry wolf.

## What exists today (read the code before changing anything)

- `walletguard/system.py`: read-only scan of Defender status and detections, Run keys, startup-folder shortcuts (resolved), non-Microsoft scheduled tasks, unsigned processes running from AppData/Temp with their network connections, and desktop wallet folders.
- `walletguard/extensions.py`: inventory of Chrome/Edge/Brave/Vivaldi/Opera/Firefox extensions in every profile, with risk scoring (fake wallet names, sideloaded installs, code injected into all sites, risky permissions, wallets sharing a profile).
- `walletguard/clipboard.py`: clipboard guard. Polls `GetClipboardSequenceNumber`. When an address is swapped within 1.5 s it restores the original, names the owner process and optionally kills it. It also warns on look-alike addresses (address poisoning), scam addresses and phishing domains.
- `walletguard/watcher.py`: extension baseline/diff covering new installs, permissions gained via updates, changed update source and removed wallets.
- `walletguard/feeds.py`: ScamSniffer (GPL-3.0 data) and MetaMask eth-phishing-detect, downloaded at runtime and cached 24 h. They are never vendored into the repo.
- `walletguard/tray.py`: pure-ctypes tray icon with menu, balloons, single-instance mutex and a feed refresh every 6 h. `autostart.py` sets the HKCU Run key.
- `walletguard/findings.py`: the `Finding(severity, category, title, detail, fix, data)` model. Severities are critical/high/medium/low/info.
- `tests/test_core.py`: unittest suite (`python -m unittest discover -s tests`).

## Hard rules

1. **Python standard library only** (ctypes/winreg/subprocess to PowerShell are fine). Adding a dependency requires a stated reason and my approval.
2. **Never read, print, log or transmit secrets.** Seed phrases, private keys, passwords and vault contents never leave memory, never go into logs or reports, and are never shown in full. Report file paths and line numbers, not the secret.
3. **No data leaves the PC** except downloading public threat feeds and read-only public lookups that I explicitly enable.
4. **Read-only by default.** Anything that changes the system (killing processes, firewall rules, quarantining files, registry or audit-policy changes) must be opt-in via a flag or a tray menu item, reversible, and logged. Never touch Windows/system processes, browsers or Explorer.
5. **Licences:** write original code. Do not copy code from GPL/AGPL or unlicensed repos. You may *read* them for ideas and cite them. Data feeds are only downloaded at runtime and must have a licence that allows it.
6. **No false-positive storms.** Every detector needs an allowlist story, sensible severities and dedupe/rate limits. My own dev tools (CutShit, Ollama, Electron dev builds, PowerShell scheduled tasks under `C:\dev`) must not show up as high.
7. Every feature ships with **unit tests** (pure logic separated from Win32, as `ClipboardPolicy` is) and keeps all existing tests green. Keep the existing CLI (`scan`, `guard`, `tray`, `install`, `uninstall`, `update-feeds`) working.
8. Match the existing code style: small modules, `Finding` objects with a plain-English `fix`, comments only where the *why* isn't obvious.

## Step 1: research first (cite sources)

Search the web and GitHub for crypto-theft techniques used in 2025–2026 and the best defensive ideas. Cover at least: infostealers (Lumma, StealC, Vidar, RedLine, Atomic and their successors), clippers, malicious/hijacked browser extensions, `--load-extension` shortcut abuse, force-installed extension policies, fake wallet apps, address poisoning, drainer sites and approval phishing, remote-access scams, DNS/hosts/proxy/root-certificate tampering, and patched wallet extension files. For each technique, record: how it works, how to detect it on Windows, and the false-positive risk. For any repo you learn from, record its URL, licence and last activity. Give me this as a short table **before** writing code.

## Step 2: implement features that the research supports, in this priority order

Skip anything the research shows is low value. Add better ideas you find, and explain why.

1. **Browser launch tampering:** shortcuts (Desktop, Start Menu, taskbar pins) and Run entries that start browsers with `--load-extension`, `--remote-debugging-port`, `--disable-extensions-except` or similar flags. Also detect `ExtensionInstallForcelist` / `ExtensionSettings` policies in HKLM/HKCU for Chrome/Edge/Brave and Firefox `policies.json`, and Developer-mode extensions.
2. **Wallet extension integrity:** hash every file of each genuine wallet extension and keep a baseline per version. Alert when files change without a version change, which indicates local patching by a stealer. Detect duplicate or "shadow" copies of wallet extensions loaded from unpacked folders.
3. **Wallet-file access monitor (admin, opt-in):** add a SACL with object-access auditing on wallet extension storage (`Local Extension Settings\<wallet id>`, `IndexedDB`, `Sync Extension Settings`) and desktop wallet folders. Read Security event 4663 (via `wevtutil` or `EvtQuery` through ctypes) and alert when a non-browser process reads them. Provide `monitor-files --enable/--disable` that cleanly installs and removes the audit settings.
4. **Live persistence watcher:** baseline Run/RunOnce, startup folders, scheduled tasks, services, WMI event subscriptions, IFEO debuggers and Winlogon shell/userinit, then alert on additions within a minute.
5. **Network trust tampering:** hosts-file entries for wallet/exchange/dApp domains, system and WinHTTP proxies, browser proxy policies, DNS servers changed to unknown resolvers, and non-Microsoft root CAs added to the user or machine store (a man-in-the-middle risk).
6. **Remote-access and scam tooling:** AnyDesk, TeamViewer, ScreenConnect, RustDesk, UltraViewer, etc. running or installed, and RDP enabled. Show these as info normally, but raise them to high when running while a wallet is open in the browser.
7. **Fake wallet apps:** for desktop wallets (Exodus, Electrum, Atomic, Ledger Live, Trezor Suite, Sparrow, Wasabi), check the Authenticode signer against the expected publisher and flag installs from Downloads/Temp.
8. **Secret exposure scan (local only, opt-in):** find files that look like they contain BIP39 mnemonics (validate the 12/24 words against the wordlist and the checksum), raw private keys, or wallet keystore JSON in user folders and screenshot folders. Report the path and type only, never the secret, and recommend moving it offline.
9. **Clipboard guard upgrades:** event-driven `AddClipboardFormatListener` instead of polling. Track the history of clipboard writers so a process that writes immediately after another process is flagged even if the timing differs. Protect against QR/"copy address" pages by checking the full address against the last address the user typed or saw (address book of trusted addresses the user marks from the tray).
10. **Behaviour signals:** browsers or wallet apps spawning PowerShell/cmd/mshta/rundll32, processes reading `Local State`/`Login Data` plus wallet folders in a short window, and newly dropped unsigned executables in AppData that make outbound connections.
11. **Hardening helper (opt-in, reversible):** show and offer to enable Controlled Folder Access (adding browsers as allowed apps), Defender ASR rules relevant to stealers, SmartScreen and PUA protection. Every change must be undoable with one command.
12. **Token approval audit (opt-in, read-only):** for EVM addresses I enter, list unlimited ERC-20/NFT approvals via public RPC or explorer APIs that need no key, and link to revoke.cash. Never sign or send anything.

## Step 3: deliver

- One feature per commit, with a clear message. Update `README.md` and the tray menu where it makes sense.
- For each feature, report: what it detects, its severity logic, how to test it safely (simulate the attack harmlessly — no real malware), its known false positives, and whether it needs admin.
- Finish with a list of ideas you rejected and why, plus anything that needs my decision (admin requirements, dependencies, privacy trade-offs).
