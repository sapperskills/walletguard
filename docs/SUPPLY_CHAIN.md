# Developer supply-chain detector

`scan` and tray scans run `walletguard/supply_chain.py`. This is a local, read-only heuristic review,
not a malware verdict or a guarantee of safety. No package is executed and no network is used.

The initial REA identity comes from the feature brief: npm `rea-agents`, repository
`github.com/morluto/rea`, website `rea.tools`. This detector does not identify a particular trojan
or use copied signatures. It also watches names resembling Claude Code, Codex and Gemini CLI.

Edit `walletguard/supply_chain_allowlist.json` to maintain exact official npm names, repository
identities (`host/owner/repo`, lowercase, no `.git`) and publisher names. Empty lists mean unknown,
not trusted or suspicious. Publisher lists initially remain empty: no publisher identity was
verified for this feature. Confirm changes independently through the official project's website.
Names are comparison targets, not exemptions: even an exact official name can have suspicious hooks.
Repository and publisher fields are self-reported and can be forged.

## Collection and privacy

Only `package.json` metadata is opened, with a 512 KiB per-file and 2,000-package limit. Immediate
packages, including scoped names, are considered; nested dependencies are not traversed.
The collector projects name, repository identity, claimed `_npmUser.name`, path, recency and two
hook flags. Script bodies, URLs with credentials, raw manifests and Run commands are never reported.
It never opens `.npmrc`, Git configuration, lockfiles, executable/script contents, wallet storage or
credential files. Do not place secrets in package metadata. Symlinks and Windows junctions at
enumerated package boundaries are skipped.

Default global locations are `%APPDATA%\npm\node_modules`, `%ProgramFiles%\nodejs\node_modules`,
and `%NPM_CONFIG_PREFIX%\node_modules` when set. npx roots are `_npx` beneath the AppData npm-cache
locations and `%NPM_CONFIG_CACHE%` when set. Immediate `C:\dev` project manifests are also reviewed
for packages or cloned projects claiming an official identity. Repository identity is read from
the manifest, not the actual Git remote: clones without that claim are outside coverage. Custom
prefixes/caches configured only in `.npmrc`, other clone locations and nested projects are not scanned.

HKCU/HKLM Run and RunOnce values are read in both registry views. The report identifies the key,
view and value index instead of recording potentially sensitive commands or value names. Indexes
can change between scans; inspect the indicated key locally. Other persistence mechanisms remain
with the existing system scanner. Both detectors can report the same entry.

Missing default folders are normal. Unreadable or malformed manifests, denied registry access and
enumeration limits produce a low coverage finding with a plain-English fix. This does not mean
that every package or startup path has been checked.

## Severity rationale and known false positives

- A name one edit or adjacent transposition from a known name, including scope impersonation, is
  medium: it warrants checking provenance but does not establish malicious intent. Short names
  under five characters are excluded from edit comparisons to reduce collisions.
- A claimed source or publisher mismatch is medium. Legitimate forks and repackaging can match.
- A shell-spawning or download-capable preinstall/install/postinstall hook is medium only when
  the manifest modification time is within seven days. Modification time is an installation proxy,
  not proof of installation time; old, preserved or attacker-controlled timestamps can evade this.
  Native installers and package-manager bootstraps are common false positives. Referenced hook files
  are not opened; arbitrary JavaScript downloader implementations are outside coverage.
- Three package indicators together rate high. Two hook indicators alone stay medium. `C:\dev`,
  CutShit, Ollama and Electron paths stay low below three indicators; they are not unconditional
  exemptions. Ordinary PowerShell use alone does not produce a finding.
- Run entries need a script suffix, a user-writable path and hidden or unusual options to rate
  medium. High requires hidden execution, unusual options and a download indicator together.
  Developer automation stays low without all three. PowerShell tasks and developer launchers can
  legitimately match. Relative paths, encoded-only payloads and exotic launchers may be missed.

Every finding provides a review/removal fix and known false positives. No automatic removal,
registry changes, process termination, or package-manager invocation is performed.

## Testing

`tests/test_supply_chain.py` uses synthetic dictionaries and temporary manifest fixtures, never the
live package directories or registry. It covers exact names, typos, scopes, forged sources,
publisher mismatches, old hooks, correlated signals, developer exceptions, Run commands, metadata
projection, malformed/oversized files, scope boundaries, enumeration limits and scanner wiring.
Run `python -m unittest discover -s tests` for the complete suite.
