# Optimizely-style compromised-page attack: WalletGuard audit

Reviewed: 2026-11-16; baseline: `main` tree `8ddb18b6b987d0c4cc64459e29ba51166e2fadf7`.

## Verdict

**Partial detection only. WalletGuard does not presently prevent a trusted site's compromised JavaScript from rewriting a recipient address in page content, a wallet request, or its UI.**

This is a code-path audit, **not a live malware test**. No malicious scripts, secrets or real funds were used. A user's visit to an affected site alone does not establish wallet compromise.

## Existing protections

- `walletguard/clipboard.py`: watches the *Windows clipboard*. If one valid same-chain address changes to another within 1.5 seconds, restores the earlier address and alerts. Warns about known bad addresses and lookalikes. This is useful against traditional clipboard clippers, **not** an authoritative source-of-truth check for a recipient.
- `walletguard/security/transaction.py`: read-only/offline analysis of an EVM transaction passed to the CLI by a user. It detects selected approval methods, native value, unknown call data, and deployments. It does not connect to a browser's wallet-approval flow, knows no intended recipient, and does not block signing.
- `walletguard/security/origins.py`: flags malformed/unusual origin characteristics. A compromised `https://` site can still have a legitimate origin and produce only an informational result.
- `walletguard/integrity.py` and `walletguard/extensions.py`: assess extensions and extension integrity. Third-party JavaScript executing in an otherwise legitimate webpage is **outside** extension-file integrity scope.
- Threat feeds detect known bad addresses/domains; a new attacker address may not be listed.

## Attack matrix

| Scenario | Current coverage | Why |
| --- | --- | --- |
| Separate local process rapidly changes a copied address | **Sometimes blocks** | Clipboard original observed, replacement observed within 1.5 s, same chain |
| Compromised page shows attacker destination **before** copy | **No reliable block** | Only the attacker's value reaches clipboard |
| Page swaps destination in outgoing wallet request | **No block** | App does not intercept wallet requests or signing |
| Malicious script steals payment card inputs or browser cookies | **No direct block** | No live DOM/content-script or network-request enforcement |
| Browser wallet extension is modified on disk | **Potentially detected** | Integrity/baseline checks cover extension files |
| HTTPS legitimate site serves compromised third-party code | **Not detected as compromised by origin check** | URL itself remains legitimate |

## Next implementation priority

1. Add **trusted-recipient verification** as an explicit opt-in, local-only policy with externally established reference addresses. Never trust the same compromised page to supply both the intended and actual recipient.
2. Integrate a supported browser-wallet signing review pathway. Deny or require explicit review when actual recipient, chain, token or amount differs from a trusted independent record. Without integration this is an *advisory checker*, not a firewall.
3. For wallet signing, show recipient, network, token, allowance and amount from actual wallet transaction fields; validate against an out-of-band recipient reference. Reject unsupported or ambiguous requests rather than stating "safe."
4. Keep local privacy design: no seed phrases, keys, private wallet contents, covert browser interception, or cloud telemetry; no automatic kills for browser processes.
5. Add harmless synthetic cases, including: legitimate site with script-tampered address; clipboard replacement outside the 1.5s window; same first/last address lookalike; altered wallet request without clipboard activity; a known phishing domain; clean browser extension with hostile page script.

## Acceptance gates

- Separate observation from prevention. Never claim an attack is blocked unless the actual signing pathway is gated.
- Tests should show that substituting an unauthorized destination fails closed once trusted-recipient verification is integrated.
- Windows-only clipboard tests run locally; read-only pure policy tests may run in CI after platform separation.
- Run `python -m unittest discover -s tests -v` on Windows; preserve `SECURITY.md` restrictions.
