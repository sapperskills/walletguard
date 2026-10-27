"""Address checksum algorithms, standard library only.

Validating the checksum (not just the shape) means the clipboard guard only treats real
addresses as addresses, and can tell when one has been altered.
"""

import base64
import hashlib

# ---------------------------------------------------------------- Keccak-256 (Ethereum, not SHA3-256)

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _M if n else v


def _keccak_f(a):
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x][y])
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc
    return a


def keccak256(data):
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * (-len(msg) % rate)
    msg[-1] |= 0x80
    a = [0] * 25
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            a[i] ^= int.from_bytes(msg[off + 8 * i: off + 8 * i + 8], "little")
        a = _keccak_f(a)
    return b"".join(a[i].to_bytes(8, "little") for i in range(4))


def eip55_valid(addr):
    """EIP-55 mixed-case checksum. All-lower or all-upper addresses carry no checksum (None)."""
    body = addr[2:]
    if body.lower() == body or body.upper() == body:
        return None
    h = keccak256(body.lower().encode()).hex()
    return all((c.upper() if int(h[i], 16) >= 8 else c.lower()) == c for i, c in enumerate(body))


# ---------------------------------------------------------------- base58 / base58check

B58_BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_XRP = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def b58decode(s, alphabet=B58_BTC):
    n = 0
    for ch in s:
        i = alphabet.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip(alphabet[0]))
    return b"\x00" * pad + raw


def b58check_decode(s, alphabet=B58_BTC):
    """Return the payload (version + data) if the 4-byte double-SHA256 checksum is valid."""
    raw = b58decode(s, alphabet)
    if not raw or len(raw) < 5:
        return None
    payload, check = raw[:-4], raw[-4:]
    return payload if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == check else None


# ---------------------------------------------------------------- bech32 / bech32m (BIP-173 / BIP-350)

BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST, BECH32M_CONST = 1, 0x2BC830A3


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def bech32_decode(s):
    """Return (hrp, data5, variant) with variant 'bech32' or 'bech32m', or None.

    No 90-character limit, because Cardano addresses are longer."""
    if s.lower() != s and s.upper() != s:
        return None
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return None
    hrp, data = s[:pos], s[pos + 1:]
    if any(c not in BECH32_CHARS for c in data):
        return None
    values = [BECH32_CHARS.find(c) for c in data]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    const = _bech32_polymod(expanded + values)
    variant = {BECH32_CONST: "bech32", BECH32M_CONST: "bech32m"}.get(const)
    return (hrp, values[:-6], variant) if variant else None


def convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or (acc << (tobits - bits)) & maxv):
        return None
    return out


def segwit_valid(hrp, data5, variant):
    """BIP-350: witness v0 must use bech32, v1+ bech32m; program length rules."""
    if not data5:
        return False
    ver, prog = data5[0], convertbits(data5[1:], 5, 8, pad=False)
    if prog is None or ver > 16 or not 2 <= len(prog) <= 40:
        return False
    if ver == 0 and len(prog) not in (20, 32):
        return False
    return variant == ("bech32" if ver == 0 else "bech32m")


# ---------------------------------------------------------------- CashAddr (Bitcoin Cash, Kaspa)

def _cashaddr_polymod(values):
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        if c0 & 1:
            c ^= 0x98F2BC8E61
        if c0 & 2:
            c ^= 0x79B76D99E2
        if c0 & 4:
            c ^= 0xF33E5FB3C4
        if c0 & 8:
            c ^= 0xAE2EABE2A8
        if c0 & 16:
            c ^= 0x1E4F43E470
    return c ^ 1


def cashaddr_valid(prefix, payload):
    payload = payload.lower()
    if any(c not in BECH32_CHARS for c in payload) or len(payload) < 9:
        return False
    values = [BECH32_CHARS.find(c) for c in payload]
    return _cashaddr_polymod([ord(c) & 0x1F for c in prefix] + [0] + values) == 0


# ---------------------------------------------------------------- CRC16-XMODEM (Stellar, TON)

def crc16_xmodem(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def stellar_valid(addr):
    try:
        raw = base64.b32decode(addr + "=" * (-len(addr) % 8))
    except ValueError:
        return False
    if len(raw) != 35 or raw[0] != 6 << 3:
        return False
    return crc16_xmodem(raw[:33]) == int.from_bytes(raw[33:], "little")


def ton_friendly_valid(addr):
    try:
        raw = base64.urlsafe_b64decode(addr.replace("+", "-").replace("/", "_"))
    except ValueError:
        return False
    if len(raw) != 36 or raw[0] & 0x7F not in (0x11, 0x51):  # bounceable / non-bounceable, +0x80 testnet
        return False
    return crc16_xmodem(raw[:34]) == int.from_bytes(raw[34:], "big")


# ---------------------------------------------------------------- SS58 (Polkadot, Kusama, Substrate)

def ss58_valid(addr):
    raw = b58decode(addr)
    if not raw or len(raw) not in (35, 36):
        return False
    prefix_len = 1 if raw[0] < 64 else 2
    body, check = raw[:-2], raw[-2:]
    if len(body) - prefix_len != 32:
        return False
    return hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2] == check


def ss58_network(addr):
    raw = b58decode(addr)
    return raw[0] if raw and raw[0] < 64 else None


# ---------------------------------------------------------------- Algorand

def algorand_valid(addr):
    try:
        raw = base64.b32decode(addr + "=" * (-len(addr) % 8))
        h = hashlib.new("sha512_256")
    except (ValueError, TypeError):
        return False
    if len(raw) != 36:
        return False
    h.update(raw[:32])
    return h.digest()[-4:] == raw[32:]
