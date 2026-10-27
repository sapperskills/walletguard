"""Reference data: genuine wallet extension IDs, browser locations, risky permissions."""

import os

LOCAL = os.environ.get("LOCALAPPDATA", "")
ROAMING = os.environ.get("APPDATA", "")

# Official store IDs of wallet extensions. Each was checked against its Chrome Web Store
# listing URL (or, for MetaMask on Edge and Solflare, a store-signed install) on 2026-10-26.
# An extension whose *name* looks like a wallet but whose ID is not here may be a fake.
WALLET_EXTENSIONS = {
    # Multichain / EVM
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask (Chrome)",
    "ejbalbakoplchlghecdalmeeeajnimhm": "MetaMask (Edge)",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
    "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
    "acmacodkjbdgmoleebolmdjonilkdbch": "Rabby",
    "mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Wallet",
    "jiidiaalihmmhddjgbnbgdfflelocpak": "Bitget Wallet",
    "klghhnkeealcohjjanjjdaeeggmfmlpl": "Zerion",
    "opfgelmcmbiajamepnmloijbpoleiama": "Rainbow",
    "eajafomhmkipbjmfmhebemolkcicgfmd": "Taho",
    "nnpmfplkfogfpmcngplhnbdnnilmcdcg": "Uniswap Extension",
    "ehgjhhccekdedpbkifaojjaefeohnoea": "Ambire",
    "heamnjbnflcikcggoiplibfommfbkjpj": "Zeal",
    "hifafgmccdpekplomjjkcfgodnhcellj": "Crypto.com Onchain",
    "agoakfejjabomempkjlepdflaleeobhb": "Core (Avalanche)",
    "kkpllkodjeloidieedojogacfhpaihoh": "Enkrypt",
    "aeachknmefphepccionboohckonoeemg": "Coin98",
    "hmeobnfnfcmdkdcmlblgagmfpfboieaf": "Ctrl (XDEFI)",
    "aholpfdialjgjfhomihkjbmgjidlcdno": "Exodus Web3",
    "gjnckgkfmgmibbkoficdidcljeaaaheg": "Atomic Wallet",
    "hpglfhgfnhbgpjdenjgmdgoeiappafln": "Guarda",
    "fiikommddbeccaoicoejoniammnalkfa": "Nightly",
    "fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin",
    "ffondjhiilhjpmfakjbejdgbemolaaho": "VeWorld (VeChain)",
    # Solana
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
    "bhhhlbepdkbapadjdnnojkbgioiodbic": "Solflare",
    "aflkmfhebedbjioipglgcbcmnbpgliof": "Backpack",
    # Bitcoin
    "ppbibelpcjmhbdihakflkdcoccbgbkpo": "UniSat",
    "idnnbdplmphpflfnlkomgpfbpcgelopg": "Xverse",
    "ldinpeekobnhjjdofggfgjlcehhmanlj": "Leather",
    "mlbnicldlpdimbjdcncnklfempedeipj": "Yours (BSV)",
    # Cosmos
    "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
    "fcfcfllfndlomdhbehjjcoimbgofdncg": "Leap",
    "fpkhgmpbidmiogeglndfbkegfdlnajnf": "Cosmostation",
    "anokgmphncpekkhclmingpimjmcooifb": "Compass (Sei)",
    # Sui / Aptos
    "opcgpfmipidbgpenhmajoajpbobppdil": "Slush (Sui Wallet)",
    "lfcmbodjdaklmnbanalifjjnkldngine": "Suiet",
    "ejjladinnckdgjemekebdpeokbikhfci": "Petra (Aptos)",
    "efbglgofoippbgcjepnhiblaibcnclgk": "Martian",
    "phkbamefinggmakgklpkljjmgibohnba": "Pontem",
    # TON
    "omaabbefbmiijedngplfjmnooppbclkk": "Tonkeeper",
    "fldfpgipfncgndfolcbkdeeknbbbnhcc": "MyTonWallet",
    # Cardano
    "gafhhkghbfjjkeiendhlofajokpaflmk": "Lace",
    "kmhcihpebfmpgmihbkipmjlmmioameka": "Eternl",
    "lpfcbjknijpeeillifnkikgncikgfhdo": "Nami",
    "ffnbelfdoeiohenkjibnmadjiehjhajb": "Yoroi",
    "kfdniefadaanbjodldohaedphafoffoh": "Typhon",
    "nhbicdelgedinnbcidconlnfeionhbml": "Begin",
    # Polkadot
    "fijngjgcjhjmmpcmkeiomlglpeiijkld": "Talisman",
    "onhogfjeacnfoofkfgppdlbmlmnplgbn": "SubWallet",
    "ginchbkmljhldofnbjabmeophlhdldgp": "PolkaGate",
    "nhlnehondigmgckngjomcpcefcdplmgc": "Fearless",
    # Starknet
    "jnlgamecbpmbajjfhmmmlhejkemejdma": "Braavos",
    "dlcobpjiigpikoobohmabehhmhfoodbb": "Ready (Argent X)",
    # Stellar
    "bcacfldlkkdogcmkkibnjlakofdplcbk": "Freighter",
    "ldiagbjmlmjiieclmdkagofdjcgodjle": "LOBSTR",
    "hgmoaheomcjnaheggkfafnjilfcefbmo": "Rabet",
    # Tron
    "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
}

FIREFOX_WALLETS = {
    "webextension@metamask.io": "MetaMask",
}

WALLET_NAME_WORDS = (
    "wallet", "metamask", "phantom", "solflare", "coinbase", "trust", "rabby",
    "keplr", "okx", "exodus", "ledger", "trezor", "tronlink", "seed", "crypto",
    "bitcoin", "ethereum", "solana", "web3", "defi", "airdrop", "keplr", "tonkeeper", "eternl", "yoroi",
    "subwallet", "polkadot", "braavos", "bitget", "zerion", "xverse", "unisat",
)  # generic words (lace, leap, rainbow, atomic…) left out: too many unrelated extensions use them

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
