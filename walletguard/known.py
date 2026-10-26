"""Reference data: genuine wallet extension IDs, browser locations, risky permissions."""

import os

LOCAL = os.environ.get("LOCALAPPDATA", "")
ROAMING = os.environ.get("APPDATA", "")

# Official store IDs of popular wallet extensions. An extension whose *name*
# looks like a wallet but whose ID is not here is treated as a possible fake.
WALLET_EXTENSIONS = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask (Chrome)",
    "ejbalbakoplchlghecdalmeeeajnimhm": "MetaMask (Edge)",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
    "bhhhlbepdkbapadjdnnojkbgioiodbic": "Solflare",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
    "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
    "acmacodkjbdgmoleebolmdjonilkdbch": "Rabby",
    "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
    "mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Wallet",
    "aflkmfhebedbjioipglgcbcmnbpgliof": "Backpack",
    "aholpfdialjgjfhomihkjbmgjidlcdno": "Exodus Web3",
    "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
    "fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin",
    "ppbibelpcjmhbdihakflkdcoccbgbkpo": "UniSat",
    "idnnbdplmphpflfnlkomgpfbpcgelopg": "Xverse",
}

FIREFOX_WALLETS = {
    "webextension@metamask.io": "MetaMask",
}

WALLET_NAME_WORDS = (
    "wallet", "metamask", "phantom", "solflare", "coinbase", "trust", "rabby",
    "keplr", "okx", "exodus", "ledger", "trezor", "tronlink", "seed", "crypto",
    "bitcoin", "ethereum", "solana", "web3", "defi", "airdrop",
)

CHROMIUM_BROWSERS = {
    "Chrome": os.path.join(LOCAL, r"Google\Chrome\User Data"),
    "Edge": os.path.join(LOCAL, r"Microsoft\Edge\User Data"),
    "Brave": os.path.join(LOCAL, r"BraveSoftware\Brave-Browser\User Data"),
    "Vivaldi": os.path.join(LOCAL, r"Vivaldi\User Data"),
    "Opera": os.path.join(ROAMING, r"Opera Software\Opera Stable"),
    "Opera GX": os.path.join(ROAMING, r"Opera Software\Opera GX Stable"),
}

FIREFOX_PROFILES = os.path.join(ROAMING, r"Mozilla\Firefox\Profiles")

DESKTOP_WALLET_DIRS = (
    "Exodus", "Electrum", "atomic", "Ledger Live", "@trezor", "Wasabi",
    "Bitcoin", "Monero", "Coinomi", "Guarda", "Jaxx", "Armory", "Sparrow",
)

# Permissions that let an extension spy on or tamper with other sites/extensions.
RISKY_PERMISSIONS = {
    "management": "can see, disable or uninstall your other extensions (including wallets)",
    "proxy": "can route all your browsing through its own servers",
    "cookies": "can read your login cookies",
    "debugger": "can attach a debugger to any tab",
    "clipboardRead": "can read your clipboard",
    "clipboardWrite": "can overwrite your clipboard",
    "nativeMessaging": "can talk to programs installed on the PC",
    "webRequestBlocking": "can rewrite web traffic",
}

ALL_SITES = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")

STORE_UPDATE_URLS = (
    "clients2.google.com/service/update2/crx",
    "edge.microsoft.com/extensionwebstorebase",
    "extension-updates.opera.com",
)

BROWSER_EXES = {
    "chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "opera.exe",
    "vivaldi.exe", "msedgewebview2.exe",
}
