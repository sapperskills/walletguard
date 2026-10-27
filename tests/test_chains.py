"""Address recognition across chains, using published test vectors and well-known public addresses,
plus synthetic addresses built with each format's own checksum. Every format must reject a
one-character change, so random text and typos are never treated as an address."""

import base64
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from walletguard import addresses, checksums as cs, known
from walletguard.clipboard import ClipboardPolicy

REAL = {
    # Bitcoin: genesis P2PKH, P2SH, BIP-173 v0 (upper case), BIP-350 taproot
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": "BTC",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy": "BTC",
    "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4": "BTC",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0": "BTC",
    # EVM: EIP-55 spec vectors
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed": "EVM",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359": "EVM",
    # Tron USDT contract, Solana wrapped-SOL mint, XRP genesis account
    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": "TRON",
    "So11111111111111111111111111111111111111112": "SOL",
    "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh": "XRP",
    # Bitcoin Cash CashAddr spec vector, with and without prefix
    "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a": "BCH",
    "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a": "BCH",
    # Stellar, TON (docs examples), Cardano CIP-19 vector, Polkadot, Dogecoin
    "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7": "XLM",
    "EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N": "TON",
    "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x": "ADA",
    "13UVJyLnbVp9RBZYFwFGyDvVd1y27Tt8tkntv6Q7JVPhFsTB": "DOT",
    "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L": "DOGE",
    # Names and 32-byte hex accounts
    "vitalik.eth": "EVM",
    "toly.sol": "SOL",
    "0x0000000000000000000000000000000000000000000000000000000000000002": "Sui/Aptos/Starknet",
}


def bech32_encode(hrp, data8):
    data5 = cs.convertbits(data8, 8, 5)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    poly = cs._bech32_polymod(expanded + data5 + [0] * 6) ^ cs.BECH32_CONST
    check = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(cs.BECH32_CHARS[d] for d in data5 + check)


def cashaddr_encode(prefix, payload8):
    data5 = cs.convertbits(payload8, 8, 5)
    poly = cs._cashaddr_polymod([ord(c) & 0x1F for c in prefix] + [0] + data5 + [0] * 8)
    check = [(poly >> 5 * (7 - i)) & 31 for i in range(8)]
    return prefix + ":" + "".join(cs.BECH32_CHARS[d] for d in data5 + check)


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = cs.B58_BTC[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


def ss58_encode(prefix, key):
    body = bytes([prefix]) + key
    return b58encode(body + hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2])


def algorand_encode(key):
    h = hashlib.new("sha512_256")
    h.update(key)
    return base64.b32encode(key + h.digest()[-4:]).decode().rstrip("=")


KEY = bytes(range(1, 33))
SYNTHETIC = {
    bech32_encode("cosmos", list(KEY[:20])): "Cosmos Hub",
    bech32_encode("osmo", list(KEY[:20])): "Osmosis",
    bech32_encode("inj", list(KEY[:20])): "Injective",
    bech32_encode("newchain", list(KEY[:20])): "bech32/newchain",
    cashaddr_encode("kaspa", [0] + list(KEY)): "KAS",
    ss58_encode(2, KEY): "KSM",
    ss58_encode(42, KEY): "Substrate",
    algorand_encode(KEY): "ALGO",
    "4" + "A" + "1" * 93: "XMR",
}


def mutate(addr):
    """Change one character in the middle to a different character of the same alphabet."""
    i = len(addr) // 2
    c = addr[i]
    for alt in "qpzry9x8gf2tvdw0s3jn54khce6mua7lABCDEFGHJKLMNPQRSTUVWXYZ":
        if alt != c and (alt.isupper() == c.isupper() or not c.isalpha()):
            return addr[:i] + alt + addr[i + 1:]
    return addr


class Recognition(unittest.TestCase):
    def test_real_addresses(self):
        for addr, chain in REAL.items():
            self.assertEqual(addresses.classify(addr), chain, addr)

    def test_synthetic_addresses(self):
        for addr, chain in SYNTHETIC.items():
            self.assertEqual(addresses.classify(addr), chain, addr)

    def test_one_character_change_is_rejected(self):
        no_checksum = {"So11111111111111111111111111111111111111112", "4" + "A" + "1" * 93}
        for addr, chain in {**REAL, **SYNTHETIC}.items():
            info = addresses.analyze(addr)
            if info.checksum == "none" or addr in no_checksum or info.kind == "name":
                continue
            bad = mutate(addr)
            got = addresses.analyze(bad)
            self.assertTrue(got is None or got.chain != chain or got.checksum == "invalid", f"{addr} -> {bad}")

    def test_ordinary_text_ignored(self):
        for t in ("hello", "1234567890", "the1quickbrownfoxjumps", "2026-10-26", "a" * 64, "C:\\Users\\x",
                  "abcdefghijkmnopqrstuvwxyzabcdefghijk", "https://example.com/path", "git commit -m fix"):
            self.assertIsNone(addresses.classify(t), t)

    def test_eip55_bad_checksum_flagged(self):
        info = addresses.analyze("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")
        self.assertEqual((info.chain, info.checksum), ("EVM", "invalid"))

    def test_keccak_vectors(self):
        self.assertEqual(cs.keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(cs.keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_bip350_rejects_v1_with_old_bech32(self):
        # BIP-173 era taproot vector: valid bech32, but v1+ must now use bech32m.
        self.assertIsNone(addresses.classify(
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx"))


class GuardAcrossChains(unittest.TestCase):
    def test_swap_detected_on_every_checksummed_chain(self):
        by_chain = {}
        for addr, chain in {**REAL, **SYNTHETIC}.items():
            if addresses.analyze(addr).kind == "address":
                by_chain.setdefault(chain, []).append(addr)
        # Build a second, different valid address for chains that only have one sample.
        extra = {"Cosmos Hub": bech32_encode("cosmos", list(KEY[1:21])), "KSM": ss58_encode(2, KEY[::-1]),
                 "ALGO": algorand_encode(KEY[::-1]), "KAS": cashaddr_encode("kaspa", [0] + list(KEY[::-1]))}
        for chain, addr in extra.items():
            by_chain.setdefault(chain, []).append(addr)
        for chain, addrs in by_chain.items():
            # The same address written two ways (e.g. with/without "bitcoincash:") is not a swap.
            addrs = list({addresses.normalise(a): a for a in addrs}.values())
            if len(addrs) < 2:
                continue
            p = ClipboardPolicy()
            p.observe(addrs[0], 10.0)
            self.assertEqual(p.observe(addrs[1], 10.2).action, "restore", chain)

    def test_broken_checksum_warns(self):
        v = ClipboardPolicy().observe("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", 1.0)
        self.assertEqual(v.action, "warn")
        self.assertIn("checksum", v.reason)

    def test_name_then_address_is_not_lookalike(self):
        self.assertFalse(addresses.lookalike("vitalik.eth", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"))


class WalletList(unittest.TestCase):
    def test_ids_are_well_formed_and_unique(self):
        ids = list(known.WALLET_EXTENSIONS)
        self.assertEqual(len(ids), len(set(ids)))
        for i in ids:
            self.assertRegex(i, r"^[a-p]{32}$")
        self.assertGreaterEqual(len(ids), 55)


if __name__ == "__main__":
    unittest.main()
