import unittest
from walletguard import addresses

# BIP-173 valid test vector (testnet, witness v0, 32-byte program)
TB = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"


class TestnetAddresses(unittest.TestCase):
    def test_testnet_segwit_is_named(self):
        self.assertEqual(addresses.classify(TB), "BTC testnet")

    def test_mainnet_unchanged(self):
        self.assertEqual(addresses.classify("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "BTC")
