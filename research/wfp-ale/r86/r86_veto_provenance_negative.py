"""R86: soundness correction to R85's synthetic classify-rights oracle.

Offline only. This proves no OS scenario is reachable; it checks which
explicit hypotheses are supported by the FWPS_CLASSIFY_OUT0 documentation.
"""
from hashlib import sha256
from itertools import product
from unittest import TestCase, main

PATHS = ("redirect_no_right", "auth_no_right", "kernel_rundown", "kernel_stop")
FAMILIES = (4, 6)
RIGHTS = (0, 1)
ACTIONS = ("PERMIT", "BLOCK", "CONTINUE", "NONE")
PROVENANCE = ("HIGHER_WEIGHT_PERMIT", "OTHER_OR_ABSENT", "UNKNOWN")


def decision(right: int, prior: str, provenance: str) -> str:
    """Do not invent provenance that FWPS_CLASSIFY_OUT0 does not attest."""
    if right:
        return "DOCUMENTED"
    if prior != "PERMIT" or provenance == "OTHER_OR_ABSENT":
        return "CONTRACT_GAP"
    if provenance == "HIGHER_WEIGHT_PERMIT":
        return "DOCUMENTED"
    return "UNPROVEN"


def matrix():
    h, counts = sha256(), {}
    for path, fam, right, prior, provenance in product(PATHS, FAMILIES, RIGHTS, ACTIONS, PROVENANCE):
        status = decision(right, prior, provenance)
        counts[status] = counts.get(status, 0) + 1
        h.update(f"{path}|{fam}|{right}|{prior}|{provenance}|{status}\n".encode())
    return sum(counts.values()), dict(sorted(counts.items())), h.hexdigest()


class NegativeTests(TestCase):
    def test_known_higher_permit_veto_documented(self):
        self.assertEqual(decision(0, "PERMIT", "HIGHER_WEIGHT_PERMIT"), "DOCUMENTED")

    def test_same_action_without_provenance_is_not_proof(self):
        self.assertEqual(decision(0, "PERMIT", "UNKNOWN"), "UNPROVEN")

    def test_non_higher_permit_is_not_documented(self):
        self.assertEqual(decision(0, "PERMIT", "OTHER_OR_ABSENT"), "CONTRACT_GAP")

    def test_no_right_nonpermit_is_not_documented(self):
        for a in ACTIONS[1:]:
            for p in PROVENANCE:
                self.assertEqual(decision(0, a, p), "CONTRACT_GAP")

    def test_with_right_is_documented_even_with_unknown_provenance(self):
        for a in ACTIONS:
            for p in PROVENANCE:
                self.assertEqual(decision(1, a, p), "DOCUMENTED")

    def test_counts_exhaustive(self):
        n, counts, _ = matrix()
        self.assertEqual(n, 192)
        self.assertEqual(counts, {"CONTRACT_GAP": 80, "DOCUMENTED": 104, "UNPROVEN": 8})


if __name__ == "__main__":
    main(exit=False, verbosity=2)
    print("R86_MATRIX", matrix())
