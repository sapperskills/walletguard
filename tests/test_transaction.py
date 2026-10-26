import unittest
from walletguard.security.transaction import analyze_transaction, analyze_sign_method, valid_address_shape

TO = "0x" + "11" * 20
SPENDER = "0x" + "22" * 20
ABI_SPENDER = "00" * 12 + "22" * 20
MAX = (1 << 256) - 1


def approval(amount):
    return "0x095ea7b3" + ABI_SPENDER + f"{amount:064x}"


def operator_approval(enabled):
    return "0xa22cb465" + ABI_SPENDER + f"{enabled:064x}"


class TransactionPolicyTests(unittest.TestCase):
    def test_unlimited_approval_high(self):
        result = analyze_transaction(to=TO, data=approval(MAX))
        self.assertEqual(result[0].severity, "high")
        self.assertEqual(result[0].data["spender"], SPENDER)

    def test_finite_approval_medium(self):
        self.assertEqual(analyze_transaction(to=TO, data=approval(250))[0].severity, "medium")

    def test_zero_approval_info_not_guaranteed_safe(self):
        self.assertEqual(analyze_transaction(to=TO, data=approval(0))[0].severity, "info")

    def test_operator_all_high(self):
        self.assertEqual(analyze_transaction(to=TO, data=operator_approval(1))[0].severity, "high")

    def test_operator_all_false_info(self):
        self.assertEqual(analyze_transaction(to=TO, data=operator_approval(0))[0].severity, "info")

    def test_operator_invalid_bool_not_assumed_true_or_false(self):
        self.assertEqual(analyze_transaction(to=TO, data=operator_approval(2))[0].category, "unverified-call")

    def test_unknown_call_not_marked_safe(self):
        self.assertEqual(analyze_transaction(to=TO, data="0x12345678")[0].category, "unverified-call")

    def test_noncanonical_address_word_not_decoded(self):
        bad = "0x095ea7b3" + "01" + "00" * 11 + "22" * 20 + f"{MAX:064x}"
        self.assertEqual(analyze_transaction(to=TO, data=bad)[0].category, "unverified-call")

    def test_native_transfer(self):
        found = analyze_transaction(to=TO, value_wei=10)
        self.assertEqual(found[0].category, "native-transfer")

    def test_deployment(self):
        found = analyze_transaction(to=None, data="0x60006000")
        self.assertEqual(found[0].category, "deployment")

    def test_invalid_destination(self):
        with self.assertRaises(ValueError):
            analyze_transaction(to="0x123", data="0x")

    def test_odd_calldata(self):
        with self.assertRaises(ValueError):
            analyze_transaction(to=TO, data="0xabc")

    def test_nongraph_calldata(self):
        with self.assertRaises(ValueError):
            analyze_transaction(to=TO, data="0xnothex")

    def test_no_to_and_no_calldata(self):
        with self.assertRaises(ValueError):
            analyze_transaction(to=None)

    def test_no_negative_wei(self):
        with self.assertRaises(ValueError):
            analyze_transaction(to=TO, value_wei=-1)

    def test_bool_not_value(self):
        with self.assertRaises(ValueError):
            analyze_transaction(to=TO, value_wei=True)

    def test_overflow_value(self):
        with self.assertRaises(ValueError):
            analyze_transaction(to=TO, value_wei=MAX + 1)

    def test_valid_address_is_shape_only(self):
        self.assertTrue(valid_address_shape(TO))
        self.assertFalse(valid_address_shape("0x" + "g" * 40))
        self.assertFalse(valid_address_shape(None))

    def test_eth_sign_warning(self):
        self.assertEqual(analyze_sign_method("eth_sign")[0].severity, "high")

    def test_typed_data_warning(self):
        self.assertEqual(analyze_sign_method("eth_signTypedData_v4")[0].severity, "medium")

    def test_unknown_signature_warning(self):
        self.assertEqual(analyze_sign_method("wallet_made_up")[0].severity, "medium")


if __name__ == "__main__":
    unittest.main()
