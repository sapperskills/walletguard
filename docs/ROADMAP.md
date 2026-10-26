# Milestones, in safety-first order

## 0 â€” Current deliverable (implemented and locally tested)

- Original MIT-licensed local policy prototype; zero secrets, zero telemetry.
- Decode canonical ERC-20 unlimited/limited allowance requests and NFT operator approvals.
- Flag unrecognized calldata, risky signature methods, dubious website origins and
  browser debug/extension launch flags.
- Offline checkers merged into the working Windows scanner, clipboard guard, extension watcher and tray app.
- Unit tests for every module, pure logic isolated from Windows collection.

## 1 â€” Watch-only wallet applications

- Choose audited/open-license wallet UI and libraries; produce SBOM.
- Windows and Android address/watch-only balance UI, configurable RPC and chain display.
- Explain RPC privacy tradeoffs and threat-feed provenance.
- Shared read-only token-approval inspector with explicit chain/address/network scope.
- No signing; testnet synthetic data; negative and error-path tests.

## 2 â€” Transaction analysis and pre-sign safeguards

- Real-world transaction simulation with independent RPC validation and honest
  uncertainty. Decode token, NFT, permit/Permit2, EIP-712, multicalls, proxies.
- User-approved domain/contract allowlists and rate-limited alerts; never silently
  mark a transaction safe based on unknown selector or no warnings.
- Device-local phishing feeds; no URL, wallet address, IP or wallet metadata
  uploads without explicit user permission. Review feed licensing.

## 3 â€” Signing with independent review

- External/security-reviewed key and signing libraries. Dedicated key boundary,
  audited hardware-wallet integrations, protected backups and restore workflow.
- Security audit + fuzz tests before production signing is enabled.
- Testnet and hardware-wallet staging; independent penetration review.

## 4 â€” Browser and device defense

- EIP-1193 and EIP-6963 extension. Chrome/Edge extensions require review of
  provider and content-script trust boundaries, permissions and store policies.
- Connect the wallet to the WalletGuard scanner in this repository (separate process, no key access).
  Preserve opt-in, reversible changes, no false-positive storms, developer allowlists.
- Android protections only within platform privacy and sandbox restrictions.

## 5 â€” Store releases

- Microsoft Store and Google Play declarations, organization account eligibility,
  signing, privacy policy and security review. Verify policies at submission time.
- CI provenance, SBOM, update signing, reproducible-build strategy, staged rollout.
- Free/open-source forever; normal chain gas fees still exist.

## Not planned

- Hosted custody; uploading seeds; in-wallet ads; arbitrary remote AI key access;
  unattended signing; trading bots with signing permission; security-through-obscurity.

