"""Deterministic targeted negatives for hypothetical R19 reauth changes."""
import unittest
from r181_reauth_matrix import rows

class ReauthGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = list(rows())

    def test_complete_matrix(self):
        self.assertEqual(len(self.matrix), 60)
        self.assertEqual(len({(x["family"], x["phase"], x["flow"], x["health"]) for x in self.matrix}), 60)

    def test_r19_blocks_every_matching_reauthorize(self):
        self.assertTrue(all(x["source"] == "BLOCK_REAUTH" for x in self.matrix))

    def test_removing_flag_guard_does_not_fix_late_reauth(self):
        for x in self.matrix:
            if x["phase"] != "issued":
                self.assertEqual(x["remove_bit_only"], "DENY")

    def test_false_positive_only_issued_which_is_not_reauth(self):
        positives = [x for x in self.matrix if x["remove_bit_only"] == "ATTEST_CANDIDATE"]
        self.assertEqual(len(positives), 2)  # 2 IP families, only fresh+healthy+selected
        self.assertTrue(all(x["phase"] == "issued" for x in positives))

    def test_naive_app_loopback_admits_sibling_direct(self):
        unsafe = [x for x in self.matrix if x["flow"] == "sibling_direct"]
        self.assertEqual(len(unsafe), 12)
        self.assertTrue(all(x["naive_app_loopback"] == "PERMIT" for x in unsafe))

    def test_naive_app_loopback_admits_reused_identity(self):
        unsafe = [x for x in self.matrix if x["flow"] in ("endpoint_aba", "pid_aba")]
        self.assertEqual(len(unsafe), 24)
        self.assertTrue(all(x["naive_app_loopback"] == "PERMIT" for x in unsafe))

    def test_naive_app_loopback_ignores_loss(self):
        self.assertTrue(any(x["health"] == "lost" and x["naive_app_loopback"] == "PERMIT" for x in self.matrix))

    def test_proxy_ssh_is_not_a_valid_receipt(self):
        self.assertTrue(all(x["naive_app_loopback"] == "BLOCK" for x in self.matrix if x["flow"] == "proxy_ssh"))

if __name__ == "__main__":
    unittest.main()
