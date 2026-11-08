"""R55 executable tiny spec; synthetic observations, NOT a native WFP oracle."""
from itertools import product
from json import dumps

GUARDS = ('dispatched', 'endpoint', 'native_join', 'original_app',
          'selected', 'tcp', 'epoch_ticket', 'session', 'not_closed',
          'not_reused', 'exit_observed_live', 'ssh_wfp_healthy')

def strict(bits):
    # Every guard is necessary; *native_join* is unproven and never inferred.
    return all(bits)

def weak(bits):
    return bits[0] and bits[1]

def observation(family, reason, owner):
    # Hidden owner cannot be reconstructed from FWP_EMPTY and absent endpoint.
    assert owner in ('selected', 'sibling')
    return (family, reason, 'reused-5-tuple', None, None, None, 'identical-closure-log')

result = {'modeled_states': 0, 'strict_assumed_permits': 0,
          'endpoint_only_permits': 0, 'endpoint_only_excess': 0,
          'undispatched_states': 0, 'identical_observation_pairs': 0,
          'single_guard_mutants_detected': 0, 'native_windows_tests': 0}
for family, reason in product((4, 6), ('CLASSIFY_COMPLETION','POLICY_CHANGE')):
    assert observation(family,reason,'selected') == observation(family,reason,'sibling')
    result['identical_observation_pairs'] += 1
    for bits in product((False, True), repeat=len(GUARDS)):
        s, w = strict(bits), weak(bits)
        result['modeled_states'] += 1
        result['strict_assumed_permits'] += int(s)
        result['endpoint_only_permits'] += int(w)
        result['endpoint_only_excess'] += int(w and not s)
        result['undispatched_states'] += int(not bits[0])
for missed in range(len(GUARDS)):
    witness = tuple(i != missed for i in range(len(GUARDS)))
    assert not strict(witness)
    assert all(v for i, v in enumerate(witness) if i != missed)
    result['single_guard_mutants_detected'] += 1
assert (result['modeled_states'],result['strict_assumed_permits'],
        result['endpoint_only_permits'], result['endpoint_only_excess'],
        result['undispatched_states'],result['identical_observation_pairs'],
        result['single_guard_mutants_detected']) == (16384,4,4096,4092,8192,4,12)
print(dumps(result, indent=2))
