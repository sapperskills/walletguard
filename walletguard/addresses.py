"""Recognise crypto addresses and spot look-alike (poisoned) addresses."""

import re

B58 = "1-9A-HJ-NP-Za-km-z"

# Most specific first: several chains share the base58 alphabet.
PATTERNS = [
    ("EVM", re.compile(r"0x[0-9a-fA-F]{40}")),
    ("BTC", re.compile(r"(bc1|BC1)[02-9ac-hj-np-zAC-HJ-NP-Z]{11,71}")),
    ("BTC", re.compile(rf"[13][{B58}]{{25,34}}")),
    ("LTC", re.compile(r"(ltc1|LTC1)[02-9ac-hj-np-zAC-HJ-NP-Z]{11,71}")),
    ("LTC", re.compile(rf"[LM][{B58}]{{26,33}}")),
    ("TRON", re.compile(rf"T[{B58}]{{33}}")),
    ("DOGE", re.compile(rf"D[5-9A-HJ-NP-U][{B58}]{{32}}")),
    ("XMR", re.compile(rf"[48][0-9AB][{B58}]{{93}}")),
    ("XRP", re.compile(rf"r[{B58}]{{24,34}}")),
    ("SOL", re.compile(rf"[{B58}]{{32,44}}")),
]


def classify(text):
    """Return the chain name if text is exactly one address, else None."""
    if not text:
        return None
    t = text.strip()
    if len(t) > 120 or any(c.isspace() for c in t):
        return None
    for chain, pat in PATTERNS:
        if pat.fullmatch(t):
            if chain == "SOL" and not _plausible_solana(t):
                return None
            return chain
    return None


def _plausible_solana(t):
    # Plain words/numbers also fit base58; real keys mix digits, upper and lower case.
    return any(c.isdigit() for c in t) and any(c.isupper() for c in t) and any(c.islower() for c in t)


def normalise(addr):
    a = addr.strip()
    return a.lower() if a.lower().startswith(("0x", "bc1", "ltc1")) else a


def body(addr):
    a = normalise(addr)
    for p in ("0x", "bc1", "ltc1"):
        if a.startswith(p):
            return a[len(p):]
    return a


def lookalike(a, b, n=4):
    """True when two different addresses share the same first or last n characters.

    That is the signature of address poisoning and of 'smart' clippers that pick a
    replacement resembling yours so a quick glance at the ends doesn't catch it.
    """
    if normalise(a) == normalise(b):
        return False
    ba, bb = body(a), body(b)
    return ba[:n] == bb[:n] or ba[-n:] == bb[-n:]


def short(addr):
    a = addr.strip()
    return a if len(a) <= 16 else f"{a[:8]}…{a[-6:]}"
