#!/usr/bin/env python3
"""Independent declarative oracle, no import from the R29 projection."""
from itertools import product

current_states = ('selected.exe', 'broker.exe', 'sibling.exe', '')
original_states = ('selected.exe', 'broker.exe', 'sibling.exe', '')
assert len(current_states) == 4 and len(original_states) == 4

checked = 0
mismatches = 0
for family, original, current in product((4, 6), original_states, current_states):
    # Observed source predicate, with all other verification fields positive:
    source_accepts = original == 'selected.exe' and current == 'selected.exe'
    # The weak *original-only* requirement is a negative-test comparator,
    # NOT an approved replacement for AUTH checking or kernel proof.
    identity_requirement = original == 'selected.exe'
    if identity_requirement and not source_accepts and current == 'broker.exe':
        mismatches += 1
    if original != 'selected.exe':
        assert not source_accepts
    checked += 1
assert (checked, mismatches) == (32, 2), (checked, mismatches)
print('R29 INDEPENDENT=32/32 source truth-table cases, '
      '2/2 conditional documented proxy current-AppId mismatches; '
      'security-positive proof=NO; native Win32/WFP=NOT_RUN')
