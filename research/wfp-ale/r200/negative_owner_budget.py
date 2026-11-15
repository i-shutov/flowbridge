"""R200 independent semantic negative tests. No OS, WFP, drivers or networking."""
import unittest

CAP = 256  # Compared independently to the pinned Rust constant by source-bound.mjs.

class LedgerModel:
    def __init__(self):
        self.owner_pids = []
        self.live = set()
        self.lost = False

    def born(self, pid):
        if self.lost:
            return "LOST"
        if pid in self.owner_pids:
            self.lost = True
            return "REUSED_PID"
        if len(self.owner_pids) == CAP:
            self.lost = True
            return "FULL"
        self.owner_pids.append(pid)
        self.live.add(pid)
        return "OK"

    def died(self, pid):
        self.live.discard(pid)

    def lookup(self, pid):
        return not self.lost and pid in self.live


class NegativeCases(unittest.TestCase):
    def test_selected_is_revoked_by_257th_unrelated_birth(self):
        m = LedgerModel()
        selected = 10
        self.assertEqual(m.born(selected), "OK")
        for pid in range(1000, 1000 + CAP - 1):
            self.assertEqual(m.born(pid), "OK")
        self.assertTrue(m.lookup(selected))
        self.assertEqual(m.born(9000), "FULL")
        self.assertFalse(m.lookup(selected))
        self.assertTrue(m.lost)

    def test_dead_unrelated_entries_still_exhaust_budget(self):
        m = LedgerModel()
        m.born(10)  # selected remains live
        for pid in range(1000, 1000 + CAP - 1):
            self.assertEqual(m.born(pid), "OK")
            m.died(pid)
        self.assertEqual(len(m.live), 1)
        self.assertEqual(m.born(9000), "FULL")
        self.assertFalse(m.lookup(10))

    def test_unrelated_births_preempt_later_selected_registration(self):
        m = LedgerModel()
        for pid in range(1000, 1000 + CAP):
            self.assertEqual(m.born(pid), "OK")
        self.assertEqual(m.born(10), "FULL")
        self.assertFalse(m.lookup(10))

    def test_full_latch_cannot_self_recover_from_exits(self):
        m = LedgerModel()
        for pid in range(1000, 1000 + CAP):
            m.born(pid)
        self.assertEqual(m.born(9000), "FULL")
        for pid in range(1000, 1000 + CAP):
            m.died(pid)
        self.assertEqual(m.born(9001), "LOST")
        self.assertFalse(m.lookup(9001))

    def test_capacity_boundary_exact(self):
        for count in (0, 1, 255, 256):
            m = LedgerModel()
            for pid in range(count):
                self.assertEqual(m.born(10000 + pid), "OK")
            self.assertEqual(len(m.owner_pids), count)
            self.assertEqual(m.born(20000), "FULL" if count == CAP else "OK")

if __name__ == "__main__":
    unittest.main(verbosity=2)
