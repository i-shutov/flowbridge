#!/usr/bin/env python3
"""R73: deterministic offline counterexample to kernel/accepted-socket CLAIM binding.
This does not call Windows, touch networks or attest physical WFP traffic.
"""
from dataclasses import dataclass, replace
import hashlib
import unittest

@dataclass(frozen=True)
class State:
    family: int = 4
    same_broker: bool = True
    ticket_live: bool = True
    auth_seen: bool = True
    owner_live: bool = True
    same_accepted_socket: bool = True
    context_queried_on_socket: bool = True
    records_queried_on_socket: bool = True
    ssh_authenticated: bool = True
    raw_claim_path: bool = False
    wfp_enforced: bool = False
    direct_blocked: bool = False


def evaluate(s: State) -> tuple[bool, bool, bool]:
    # Kernel CLAIM's source-derived fields: broker process + valid one-shot
    # AUTH-attested receipt + owner liveness. No accepted SOCKET arrives.
    kernel = s.same_broker and s.ticket_live and s.auth_seen and s.owner_live
    # The normal Received ownership discipline is a user-mode TCB assumption.
    typed = (kernel and s.same_accepted_socket and s.context_queried_on_socket
             and s.records_queried_on_socket and s.ssh_authenticated
             and not s.raw_claim_path)
    # A strict hypothetical physical assertion needs separate evidence.
    physical = typed and s.wfp_enforced and s.direct_blocked
    return kernel, typed, physical


# 11 independent booleans (family is a separate axis): all 4096 states/family.
FIELDS = tuple(k for k in State.__dataclass_fields__ if k != 'family')
assert len(FIELDS) == 11

def audit() -> tuple[str, dict]:
    digest = hashlib.sha256()
    totals = {'states': 0, 'kernel': 0, 'typed': 0, 'physical': 0,
              'kernel_without_pair': 0, 'raw_bypass_candidate': 0}
    for family in (4, 6):
        for bits in range(1 << len(FIELDS)):
            args = {field: bool(bits & (1 << index))
                    for index, field in enumerate(FIELDS)}
            s = State(family=family, **args)
            k, t, p = evaluate(s)
            digest.update(bytes((int(k) | (int(t) << 1) | (int(p) << 2),)))
            totals['states'] += 1
            totals['kernel'] += int(k)
            totals['typed'] += int(t)
            totals['physical'] += int(p)
            totals['kernel_without_pair'] += int(k and not s.same_accepted_socket)
            totals['raw_bypass_candidate'] += int(k and s.raw_claim_path)
    return digest.hexdigest(), totals


class R73NegativeTests(unittest.TestCase):
    def test_source_trust_distinction(self):
        self.assertEqual(evaluate(State()), (True, True, False))
    def test_ticket_swap_preserves_kernel_claim(self):
        original = State()
        swapped = replace(original, same_accepted_socket=False)
        self.assertEqual(evaluate(original)[0], evaluate(swapped)[0])
        self.assertFalse(evaluate(swapped)[1])
    def test_authorized_broker_raw_command_bypasses_type_discipline(self):
        s = replace(State(), raw_claim_path=True)
        self.assertTrue(evaluate(s)[0]); self.assertFalse(evaluate(s)[1])
    def test_context_records_must_come_from_same_socket(self):
        for name in ('context_queried_on_socket', 'records_queried_on_socket'):
            s = replace(State(), **{name: False})
            self.assertTrue(evaluate(s)[0]); self.assertFalse(evaluate(s)[1])
    def test_process_death(self):
        self.assertEqual(evaluate(replace(State(), owner_live=False)), (False, False, False))
    def test_broker_mismatch(self):
        self.assertEqual(evaluate(replace(State(), same_broker=False)), (False, False, False))
    def test_one_time_auth(self):
        for name in ('ticket_live', 'auth_seen'):
            self.assertFalse(evaluate(replace(State(), **{name: False}))[0])
    def test_ssh_failure_not_kernel_rejected(self):
        s = replace(State(), ssh_authenticated=False)
        self.assertEqual(evaluate(s), (True, False, False))
    def test_physical_requires_external_proofs(self):
        for name in ('wfp_enforced', 'direct_blocked'):
            s = replace(replace(State(), wfp_enforced=True, direct_blocked=True), **{name:False})
            self.assertFalse(evaluate(s)[2])
    def test_hypothetical_full_proof_is_not_observed(self):
        s = replace(State(), wfp_enforced=True, direct_blocked=True)
        self.assertEqual(evaluate(s), (True, True, True))
    def test_same_tuple_is_not_a_socket_proof(self):
        # No 5-tuple in CLAIM API; changing only alleged socket ownership is sufficient.
        self.assertTrue(evaluate(replace(State(), same_accepted_socket=False))[0])
    def test_ipv4_ipv6_same_result(self):
        self.assertEqual(evaluate(State(family=4)), evaluate(State(family=6)))


if __name__ == '__main__':
    unittest.main(exit=False, verbosity=2)
    sha, counts = audit()
    print('R73 stream_sha256=' + sha)
    print('R73 counts=' + str(counts))
