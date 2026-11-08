#!/usr/bin/env python3
"""R41 independent pure truth table: no imports from model or Windows APIs."""
from itertools import product
cases = 0
mismatch = 0
for ipv6, selected_dead, broker_dead, ledger_poisoned, ssh_lost, claimed, buffered in product((False, True), repeat=7):
    cases += 1
    stop = broker_dead or ledger_poisoned
    source_may_copy = claimed and buffered and not ssh_lost and not stop
    owner_liveness_oracle = source_may_copy and not selected_dead
    if source_may_copy and not owner_liveness_oracle:
        mismatch += 1
        assert selected_dead and not broker_dead and not ledger_poisoned
        assert not ssh_lost and claimed and buffered
    if broker_dead or ledger_poisoned or ssh_lost or not claimed or not buffered:
        assert not source_may_copy
assert (cases, mismatch) == (128, 2), (cases, mismatch)
print(f"PASS {cases} independent worlds; {mismatch} post-CLAIM strict-liveness counterexamples")
print("Only a conditional user-mode source model; no Windows/native/physical traffic proof")
