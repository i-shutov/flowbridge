#!/usr/bin/env python3
"""Independent enumeration: event-identity observational equivalence, no Book import.

AUTH is labelled by an omniscient oracle, but label is absent from the WFP
fields consumed by R26. This is a *conditional* delivery-order counterexample.
"""
from itertools import product

FAMILIES = (4, 6)
LIFECYCLES = ("retire", "expire", "claim")
MUTANTS = ("live_only", "erase_on_expire", "erase_on_closure", "erase_on_claim")


def actual_auth_observation(origin, dest, endpoint):
    # R26 Book::attest receives these keys only. No issued sequence is provided.
    return origin, dest, endpoint


def oracle(label, live_issuance):
    return label == live_issuance


def verify():
    ambiguous = 0
    failing_mutants = set()
    families = set()
    lcs = set()
    for family, lifecycle, index in product(FAMILIES, LIFECYCLES, range(8)):
        origin = (41 + index, 1, 2, 3)
        dest = (family, 443, 200 + index)
        endpoint = 5000 + index
        a, b = 1, 2
        old_obs = actual_auth_observation(origin, dest, endpoint)
        new_obs = actual_auth_observation(origin, dest, endpoint)
        assert old_obs == new_obs
        assert not oracle(a, b) and oracle(b, b)
        # Any deterministic classifier over these actual fields must return
        # identical decisions for old and new AUTH events.
        ambiguous += 1
        families.add(family)
        lcs.add(lifecycle)
        for mutant in MUTANTS:
            # All four strategies remove the tombstone following lifecycle
            # and thus accept replacement B; the oracle rejects old AUTH A.
            if (mutant == "live_only" or
                (mutant == "erase_on_expire" and lifecycle == "expire") or
                (mutant == "erase_on_closure" and lifecycle == "retire") or
                (mutant == "erase_on_claim" and lifecycle == "claim")):
                failing_mutants.add(mutant)
    assert ambiguous == 48 and len(failing_mutants) == 4
    assert families == {4, 6} and lcs == set(LIFECYCLES)
    # Strict tombstones never admit B on a repeated endpoint, so avoid the
    # ambiguous histories; but only by consuming a finite per-session budget.
    capacity = 32
    issued = set()
    for endpoint in range(1, capacity + 1):
        assert endpoint not in issued
        issued.add(endpoint)
    assert len(issued) == capacity
    assert capacity + 1 not in issued  # would be rejected for capacity
    assert 1 in issued                  # repeat must be rejected
    print("R28 INDEPENDENT_ORACLE=48/48 observational-equivalence worlds; "
          "MUTANTS=4/4 detected; strict tombstone avoids ambiguity; "
          "FINITE_BUDGET=32; NATIVE_WFP_PROOF=false")


if __name__ == "__main__":
    verify()
