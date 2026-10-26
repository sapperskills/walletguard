# Proposed architecture (not yet implemented)

```text
Untrusted dApp web page
  | limited EIP-1193 provider / EIP-6963 discovery
  v
Browser extension UI + isolated background policy broker
  | never contains decrypted private keys in content scripts
  v
Permission + security policy engine
  | explicit approval, validate chain, spender, simulation, origin
  v
Isolated signing boundary (planned; reviewed audited dependencies)
  | Android: platform-backed secure storage / biometric UX
  | Windows: OS-protected key material + explicit unlock
  | Hardware-wallet adapters: independent confirmation display
  v
Signed tx -> user-selected blockchain RPC

Optional Windows security companion (separate trust boundary)
  | read-only scanner by default
  | explicit owner opt-in for any firewall, audit, quarantine, process kill
  | no signing or vault access
```

**MVP:** EVM first, watch-only first. Solana/XRPL require independent chain-specific
threat models and libraries. The Python reference policies in this repository
are **not** the mobile/browser production implementation. Claude should design
a cross-platform security core and validate equivalence against shared fixtures.

**No cloud means:** No account server, telemetry, backup upload or automatic
signing remote service. It does not imply no RPC queries. Default endpoint and
metadata privacy must be disclosed. Full offline capability needs local blockchain
state or an offline-sign / online-broadcast workflow.

**Standards to target:** EIP-1193 provider interface; EIP-6963 multi-provider
discovery; EIP-712 typed-data domain and message decoding; ERC-20/721/1155 ABI;
EIP-155 replay protection. These are future implementation requirements, not
claims of current compatibility.

Sources:
- https://eips.ethereum.org/EIPS/eip-1193
- https://eips.ethereum.org/EIPS/eip-6963
- https://eips.ethereum.org/EIPS/eip-712

Consider Rust-based shared core for extension/Windows/Android where feasible,
subject to independent crypto-library and FFI security review. The Python
standard-library-only prototype remains isolated from actual signing code.
