"""R85 finite negative cases: WFP classify action-write contract, no OS access.

This models ONLY unconditional BLOCK assignment in four R19 source branches.
It does not assert that every input can occur in actual WFP dispatch.
"""
import hashlib
import itertools
import unittest

PATHS = ("redirect_no_right", "auth_no_right", "kernel_rundown", "kernel_stop")
ACTIONS = ("PERMIT", "BLOCK", "CONTINUE", "NONE")

def classify(path, family, write_right, prior):
    assert path in PATHS and family in (4, 6) and prior in ACTIONS
    post_action = "BLOCK"
    post_right = False
    allowed = bool(write_right) or prior == "PERMIT"
    return (post_action, post_right, "DOCUMENTED" if allowed else "CONTRACT_GAP")

def matrix():
    digest = hashlib.sha256()
    counts = {}
    total = 0
    for case in itertools.product(PATHS, (4, 6), (0, 1), ACTIONS):
        label = classify(*case)[2]
        digest.update(('|'.join(map(str, case))+'|'+label+'\n').encode())
        counts[label] = counts.get(label, 0) + 1
        total += 1
    return total, digest.hexdigest(), dict(sorted(counts.items()))

class ContractTests(unittest.TestCase):
    def test_no_right_prior_permit_is_documented_veto(self):
        for path in PATHS:
            for family in (4, 6):
                self.assertEqual(classify(path, family, 0, "PERMIT")[2], "DOCUMENTED")
    def test_no_right_nonpermit_has_no_write_permission(self):
        for path, family, action in itertools.product(PATHS, (4, 6), ("BLOCK", "CONTINUE", "NONE")):
            self.assertEqual(classify(path, family, 0, action)[2], "CONTRACT_GAP")
    def test_write_right_allows_block(self):
        for path, family, action in itertools.product(PATHS, (4, 6), ACTIONS):
            self.assertEqual(classify(path, family, 1, action)[2], "DOCUMENTED")
    def test_matrix_counts(self):
        n, _, counts = matrix()
        self.assertEqual(n, 64)
        self.assertEqual(counts, {"CONTRACT_GAP": 24, "DOCUMENTED": 40})

if __name__ == "__main__":
    unittest.main(exit=False, verbosity=2)
    print("R85_MATRIX", matrix())
