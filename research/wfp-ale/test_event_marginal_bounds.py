"""R10 independent offline negative tests: no Windows, sockets or WFP changes."""
import itertools
import unittest
from copy import deepcopy
import event_marginal_bounds as a

def oracle(n, x, y):
    sets_x = [set(v) for v in itertools.combinations(range(n), x)]
    sets_y = [set(v) for v in itertools.combinations(range(n), y)]
    sizes = [len(p & q) for p in sets_x for q in sets_y]
    return min(sizes), max(sizes)

def fixture():
    e = {
        "kind": "read_only_wfp_exact_filter_drop_correlation",
        "query_succeeded": True, "active_qa_filter_verified": True,
        "event_collection_proven": True, "file_handle_native_identity_compared": True,
        "filter_id_redacted": True, "read_only": True, "redacted": True,
        "release_accepted": False, "kernel_packet_owner_bound": False,
        "protected_fail_closed": False, "filter_or_auditing_changed": False,
        "event_appid_expected_source_identity_complete": False,
        "selected_input_appid_equals_handle_canonical": False,
        "other_input_appid_equals_handle_canonical": False,
        "exact_qa_filter_classify_drops": 3, "bounded_scan_max": 256,
        "selected_event_appid_matches": 0, "other_event_appid_matches": 0,
        "python_event_appid_matches": 1, "agent_event_appid_matches": 0,
        "other_or_unresolved_event_appid": 2,
        "exact_filter_events_without_appid": 0,
        "selected_native_handle_path_event_matches": 1,
        "selected_canonical_handle_appid_event_matches": 1,
        "other_native_handle_path_event_matches": 1,
        "other_canonical_handle_appid_event_matches": 1,
        "selected_basename_only_matches": 1, "other_basename_only_matches": 1,
        "selected_appid_ascii_case_only_matches": 0,
        "event_appid_utf16_path_shape_valid": 3,
        "unrelated_filter_classify_drops_same_port": 0,
    }
    return e

class IndependentOracle(unittest.TestCase):
    def test_exhaustive_139_pairs(self):
        checks = 0
        for n in range(1, 7):
            for x in range(n + 1):
                for y in range(n + 1):
                    self.assertEqual(a.intersection_bounds(n, x, y), oracle(n, x, y))
                    checks += 1
        self.assertEqual(checks, 139)

    def test_disjoint_events_same_marginals(self):
        aligned = [(1, 1), (0, 0), (0, 0)]
        disjoint = [(1, 0), (0, 1), (0, 0)]
        for matrix in (aligned, disjoint):
            self.assertEqual([sum(p) for p in zip(*matrix)], [1, 1])
        self.assertEqual(sum(x and y for x, y in aligned), 1)
        self.assertEqual(sum(x and y for x, y in disjoint), 0)

    def test_canonical_appid_marginals_never_prove_joint(self):
        report = a.analyze_event(fixture())
        self.assertEqual(report["same_event_joint_pairs_proved"], 0)
        self.assertEqual(report["same_event_joint_pairs_possible_upper"], 2)
        self.assertEqual(report["marginal_pairs"]["selected"]["same_event_joint_lower"], 0)
        self.assertFalse(report["marginal_pairs"]["other"]["same_event_joint_observed"])

    def test_primary_partition_must_be_exhaustive(self):
        e = fixture()
        e["other_or_unresolved_event_appid"] = 1
        with self.assertRaises(a.InvalidEvidence):
            a.analyze_event(e)

    def test_untrusted_boolean_counts_rejected(self):
        for x in (True, False, "1", 4, -1, None, 1.0):
            with self.subTest(x=x):
                e = fixture()
                e["selected_native_handle_path_event_matches"] = x
                with self.assertRaises(a.InvalidEvidence):
                    a.analyze_event(e)

    def test_unauthorized_authority_promotion_rejected(self):
        for field in ("release_accepted", "kernel_packet_owner_bound",
                      "event_appid_expected_source_identity_complete",
                      "selected_input_appid_equals_handle_canonical"):
            with self.subTest(field=field):
                e = fixture()
                e[field] = True
                with self.assertRaises(a.InvalidEvidence):
                    a.analyze_event(e)

    def test_no_missing_evidence(self):
        e = fixture()
        del e["selected_canonical_handle_appid_event_matches"]
        with self.assertRaises(a.InvalidEvidence):
            a.analyze_event(e)

    def test_only_verified_filter_counts(self):
        e = fixture()
        e["active_qa_filter_verified"] = False
        with self.assertRaises(a.InvalidEvidence):
            a.analyze_event(e)

    def test_forced_intersection_is_not_always_zero(self):
        self.assertEqual(a.intersection_bounds(3, 2, 2), (1, 2))
        self.assertEqual(a.intersection_bounds(3, 1, 1), (0, 1))

if __name__ == "__main__":
    unittest.main(verbosity=2)
