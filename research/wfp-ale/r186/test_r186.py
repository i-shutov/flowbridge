"""R186 inventory false-assurance and ACL/transaction regression tests."""
import unittest
from r186_inventory_model import calculate, rows


class InventoryTests(unittest.TestCase):
    def test_readback_can_bridge_dead_owner_gap(self):
        # Four reads while owner A is alive; four reads after B replaces it.
        r = calculate("churn", "00002222", False, False)
        self.assertTrue(r["naive_green"])
        self.assertTrue(r["mixed_epochs"])
        self.assertFalse(r["continuous_coverage_proven"])

    def test_live_gap_is_observed_if_probed(self):
        r = calculate("churn", "00001122", False, False)
        self.assertFalse(r["read_ok"])
        self.assertFalse(r["naive_green"])

    def test_consistent_read_transaction_is_only_a_snapshot(self):
        r = calculate("churn", "00002222", False, True)
        self.assertTrue(r["naive_green"])
        self.assertFalse(r["mixed_epochs"])
        self.assertEqual(r["status"], "OWN_OBJECTS_SNAPSHOT_ONLY")
        self.assertFalse(r["continuous_coverage_proven"])

    def test_cannot_infer_hidden_competitors_from_own_guids(self):
        a = calculate("stable", "00000000", False, True)
        b = calculate("stable", "00000000", True, True)
        public = ("naive_green", "read_ok", "registered", "observed_epochs", "status")
        self.assertEqual(tuple(a[x] for x in public), tuple(b[x] for x in public))
        self.assertFalse(b["enforcement_proven"])

    def test_registered_flag_is_real_observable_state(self):
        r = calculate("unregistered", "22222222", False, True)
        self.assertFalse(r["registered"])
        self.assertFalse(r["naive_green"])

    def test_all_rows_have_no_network_proof(self):
        data = list(rows())
        self.assertEqual(len(data), 540)
        self.assertTrue(all(not r["enforcement_proven"]
                            and not r["continuous_coverage_proven"] for r in data))

    def test_mutant_ignoring_registration_is_caught(self):
        r = calculate("unregistered", "22222222", False, True)
        mutant = r["read_ok"]  # incorrectly assumes object existence => healthy
        self.assertTrue(mutant)
        self.assertNotEqual(mutant, r["naive_green"])


if __name__ == "__main__":
    unittest.main()
