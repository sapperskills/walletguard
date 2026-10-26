"""Offline, read-only EVM transaction inspection. No signing or RPC access.

Only a few known ABI selectors are decoded. Findings must never be interpreted
as transaction safety guarantees: unknown signatures, delegatecalls, routers,
proxies, phishing, malicious contracts, offchain permits, and current approvals
need a separate trusted simulation and chain-state service.
"""
import re
from walletguard.findings import Finding

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
_MAX_UINT256 = (1 << 256) - 1


def valid_address_shape(address: str) -> bool:
    """Format only, not EIP-55 checksumming or proof of ownership."""
    return isinstance(address, str) and bool(_ADDRESS.fullmatch(address))


def _word_address(word: bytes) -> str:
    if len(word) != 32 or any(word[:12]):
        raise ValueError("noncanonical ABI address")
    return "0x" + word[12:].hex()


def analyze_transaction(*, to: str | None, data: str = "0x", value_wei: int = 0) -> list[Finding]:
    """Analyze *public transaction fields* supplied by a caller.

    Deliberately does not contact an RPC server or read a wallet. Caller must
    validate chain, account and current token state separately.
    """
    if to is not None and not valid_address_shape(to):
        raise ValueError("to must be a 20-byte 0x EVM address (format only)")
    if type(value_wei) is not int or value_wei < 0 or value_wei > _MAX_UINT256:
        raise ValueError("value_wei must be an unsigned 256-bit integer")
    if not isinstance(data, str) or not _HEX.fullmatch(data):
        raise ValueError("data must be a 0x-prefixed, even-length hex byte string")
    payload = bytes.fromhex(data[2:])
    if to is None and not payload:
        raise ValueError("a transaction must specify a destination or deployment data")

    findings: list[Finding] = []
    if to is None:
        findings.append(Finding(
            "high", "deployment", "Contract deployment request",
            "This operation creates a contract; the local analyzer cannot inspect its behavior.",
            "Review verified source and run a trusted simulation before approving."))
    if value_wei:
        findings.append(Finding(
            "medium", "native-transfer", "Native cryptocurrency could be sent",
            f"The request includes {value_wei} wei of native value (network not verified).",
            "Verify the recipient, network and amount on a trusted display.",
            {"value_wei": str(value_wei)}))

    selector = payload[:4].hex() if len(payload) >= 4 else ""
    arguments = payload[4:]
    if selector == "095ea7b3" and len(arguments) == 64:  # ERC-20 approve(address,uint256)
        try:
            spender = _word_address(arguments[:32])
        except ValueError:
            findings.append(_opaque())
        else:
            allowance = int.from_bytes(arguments[32:], "big")
            if allowance == _MAX_UINT256:
                findings.append(Finding(
                    "high", "token-approval", "Unlimited ERC-20 allowance requested",
                    f"A contract at {spender} would receive the maximum possible token allowance from this token contract.",
                    "Avoid unlimited approvals when possible; verify the token and spender and consider a limited allowance.",
                    {"spender": spender, "allowance": str(allowance)}))
            elif allowance:
                findings.append(Finding(
                    "medium", "token-approval", "ERC-20 allowance requested",
                    f"A spender at {spender} is requested to receive a nonzero allowance ({allowance} base units).",
                    "Review the spender and intended token amount before signing.",
                    {"spender": spender, "allowance": str(allowance)}))
            else:
                findings.append(Finding(
                    "info", "token-approval", "ERC-20 allowance set to zero",
                    f"The request asks to set {spender}'s token allowance to zero; onchain effects are not verified.",
                    "Verify that the spender and token contract are correct.",
                    {"spender": spender, "allowance": "0"}))
    elif selector == "a22cb465" and len(arguments) == 64:  # ERC-721/1155 setApprovalForAll(address,bool)
        try:
            operator = _word_address(arguments[:32])
        except ValueError:
            findings.append(_opaque())
        else:
            approved = int.from_bytes(arguments[32:], "big")
            if approved == 1:
                findings.append(Finding(
                    "high", "nft-approval", "Approval for all NFTs requested",
                    f"Operator {operator} is requested to manage all applicable NFTs in the collection.",
                    "Confirm the collection and operator; this can enable asset transfers.",
                    {"operator": operator, "approved": True}))
            elif approved == 0:
                findings.append(Finding(
                    "info", "nft-approval", "NFT operator permission removal requested",
                    f"The request asks to revoke operator {operator} in this collection.",
                    "Verify the NFT contract and operator.",
                    {"operator": operator, "approved": False}))
            else:
                findings.append(_opaque())
    elif payload:
        findings.append(_opaque())

    if not findings:
        findings.append(Finding(
            "info", "scope", "No known risky selector found",
            "This is not a safety verdict. The analyzer has no blockchain state or simulation.",
            "Independently verify the destination, network and any transaction effects."))
    return findings


def _opaque() -> Finding:
    return Finding(
        "medium", "unverified-call", "Contract call not understood",
        "The calldata is not one of the narrowly supported canonical approval encodings.",
        "Do not infer safety; inspect verified ABI/source and use independent simulation.")


def analyze_sign_method(method: str) -> list[Finding]:
    """Signature-method metadata only; never pass message data or secrets here."""
    if method == "eth_sign":
        return [Finding("high", "signature", "Raw signing request",
                        "Raw signing can hide what a signature authorizes.",
                        "Reject unexplained raw-signature prompts; inspect the source and exact request.")]
    if method in {"personal_sign", "eth_signTypedData", "eth_signTypedData_v3", "eth_signTypedData_v4"}:
        return [Finding("medium", "signature", "Message signature requested",
                        "A signature may have meaningful authorization effects, including permits and offchain orders.",
                        "Review the complete human-readable message and domain; verify the requesting site.")]
    return [Finding("medium", "signature", "Unknown or unreviewed method",
                    "This method has not been examined by the local security policy.",
                    "Review complete payload semantics before authorizing.")]
