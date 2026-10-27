"""Recognise crypto addresses (with checksum validation) and spot look-alike (poisoned) addresses.

Checksums are verified wherever the format has one, so random text that merely looks like
an address is ignored, and an EVM address whose EIP-55 checksum is wrong is flagged.
"""

import re
from dataclasses import dataclass

from . import checksums as cs

B58 = "1-9A-HJ-NP-Za-km-z"

# Bech32 prefixes -> chain names. Any other prefix with a valid bech32 checksum is still
# recognised (as "bech32/<prefix>"), which covers every Cosmos SDK chain automatically.
BECH32_CHAINS = {
    "bc": "BTC", "ltc": "LTC", "tb": "BTC testnet", "addr": "ADA",
    "cosmos": "Cosmos Hub", "osmo": "Osmosis", "juno": "Juno", "stars": "Stargaze", "inj": "Injective",
    "sei": "Sei", "celestia": "Celestia", "dydx": "dYdX", "akash": "Akash", "kava": "Kava", "terra": "Terra",
    "secret": "Secret", "axelar": "Axelar", "noble": "Noble", "stride": "Stride", "neutron": "Neutron",
    "kujira": "Kujira", "archway": "Archway", "dym": "Dymension", "evmos": "Evmos", "persistence": "Persistence",
    "regen": "Regen", "umee": "Umee", "saga": "Saga", "band": "Band", "cro": "Cronos POS", "thor": "THORChain",
    "maya": "Maya", "xion": "XION", "one": "Harmony", "erd": "MultiversX", "zil": "Zilliqa", "init": "Initia",
    "bbn": "Babylon", "mantra": "MANTRA", "elys": "Elys", "nibi": "Nibiru", "omniflix": "OmniFlix",
}
BASE58CHECK_VERSIONS = {
    b"\x00": "BTC", b"\x05": "BTC", b"\x30": "LTC", b"\x32": "LTC", b"\x1e": "DOGE", b"\x16": "DOGE",
    b"\x41": "TRON", b"\x4c": "DASH", b"\x10": "DASH", b"\x1c\xb8": "ZEC", b"\x1c\xbd": "ZEC",
}
SS58_NETWORKS = {0: "DOT", 2: "KSM", 42: "Substrate"}
NAME_TLDS = {"eth": "EVM", "sol": "SOL", "ton": "TON", "near": "NEAR"}

RE_NAME = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)*\.(eth|sol|ton|near)")
RE_EVM = re.compile(r"0x[0-9a-fA-F]{40}")
RE_HEX64 = re.compile(r"0x[0-9a-fA-F]{61,64}")          # Sui, Aptos, Starknet
RE_TON_RAW = re.compile(r"-?\d{1,3}:[0-9a-fA-F]{64}")
RE_CASH_BARE = re.compile(r"[qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41}")
RE_STELLAR = re.compile(r"G[A-Z2-7]{55}")
RE_ALGO = re.compile(r"[A-Z2-7]{58}")
RE_TON_FRIENDLY = re.compile(r"[A-Za-z0-9_\-+/]{48}")
RE_XRP = re.compile(r"r[1-9A-HJ-NP-Za-km-z]{24,34}")
RE_XMR = re.compile(rf"[48][0-9AB][{B58}]{{93}}")
RE_ADA_BYRON = re.compile(rf"(Ae2|DdzFf)[{B58}]{{40,120}}")
RE_B58 = re.compile(rf"[{B58}]{{25,50}}")


@dataclass(frozen=True)
class Address:
    text: str
    chain: str
    kind: str = "address"      # address | name
    checksum: str = "valid"    # valid | invalid | none (format has no checksum)
    body: str = ""


def analyze(text):
    """Return an Address if text is exactly one address or wallet name, else None."""
    if not text:
        return None
    t = text.strip()
    if not t or len(t) > 130 or any(c.isspace() for c in t):
        return None
    low = t.lower()

    if RE_NAME.fullmatch(low):
        return Address(t, NAME_TLDS[low.rsplit(".", 1)[1]], "name", "none", low)
    if RE_EVM.fullmatch(t):
        ok = cs.eip55_valid(t)
        return Address(t, "EVM", checksum={None: "none", True: "valid", False: "invalid"}[ok], body=low[2:])
    if RE_HEX64.fullmatch(t):
        return Address(t, "Sui/Aptos/Starknet", checksum="none", body=low[2:].lstrip("0"))
    if RE_TON_RAW.fullmatch(t):
        return Address(t, "TON", checksum="none", body=low.split(":", 1)[1])

    for prefix, chain in (("bitcoincash:", "BCH"), ("kaspa:", "KAS")):
        if low.startswith(prefix):
            payload = low[len(prefix):]
            return Address(t, chain, body=payload) if cs.cashaddr_valid(prefix[:-1], payload) else None
    if RE_CASH_BARE.fullmatch(low) and cs.cashaddr_valid("bitcoincash", low):
        return Address(t, "BCH", body=low)

    if "1" in t and t.isalnum():
        d = cs.bech32_decode(t)
        if d:
            hrp, data5, variant = d
            if hrp in ("bc", "ltc", "tb"):
                if not cs.segwit_valid(hrp, data5, variant):
                    return None
            elif variant != "bech32":
                return None
            return Address(t, BECH32_CHAINS.get(hrp, f"bech32/{hrp}"), body=low[len(hrp) + 1:])

    if RE_STELLAR.fullmatch(t) and cs.stellar_valid(t):
        return Address(t, "XLM", body=t[1:])
    if RE_ALGO.fullmatch(t) and cs.algorand_valid(t):
        return Address(t, "ALGO", body=t)
    if RE_TON_FRIENDLY.fullmatch(t) and t[:2] in ("EQ", "UQ", "kQ", "0Q", "Ef", "Uf") and cs.ton_friendly_valid(t):
        return Address(t, "TON", body=t[2:])
    if RE_XRP.fullmatch(t):
        p = cs.b58check_decode(t, cs.B58_XRP)
        if p and p[:1] == b"\x00" and len(p) == 21:
            return Address(t, "XRP", body=t)
    if RE_XMR.fullmatch(t):
        return Address(t, "XMR", checksum="none", body=t)
    if RE_ADA_BYRON.fullmatch(t):
        return Address(t, "ADA", checksum="none", body=t)

    if RE_B58.fullmatch(t):
        p = cs.b58check_decode(t)
        if p:
            for ver, chain in BASE58CHECK_VERSIONS.items():
                if p.startswith(ver) and len(p) == len(ver) + 20:
                    return Address(t, chain, body=t)
        if cs.ss58_valid(t):
            net = cs.ss58_network(t)
            return Address(t, SS58_NETWORKS.get(net, f"SS58/{net}"), body=t)
        raw = cs.b58decode(t)
        if raw is not None and len(raw) == 32 and 32 <= len(t) <= 44:
            return Address(t, "SOL", checksum="none", body=t)
    return None


def classify(text):
    """The chain name if text is exactly one address or wallet name, else None."""
    a = analyze(text)
    return a.chain if a else None


def normalise(addr):
    a = analyze(addr)
    return a.body if a else addr.strip()


def body(addr):
    return normalise(addr)


def lookalike(a, b, n=4):
    """True when two different addresses share the same first or last n characters.

    That is the signature of address poisoning and of 'smart' clippers that pick a
    replacement resembling yours so a quick glance at the ends doesn't catch it.
    """
    aa, bb = analyze(a), analyze(b)
    if not aa or not bb or "name" in (aa.kind, bb.kind) or aa.body == bb.body:
        return False
    return aa.body[:n] == bb.body[:n] or aa.body[-n:] == bb.body[-n:]


def short(addr):
    a = addr.strip()
    return a if len(a) <= 16 else f"{a[:8]}…{a[-6:]}"
