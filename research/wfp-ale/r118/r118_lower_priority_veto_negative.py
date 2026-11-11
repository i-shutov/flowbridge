#!/usr/bin/env python3
"""Pure arbitration counterexample: NOT a WFP emulator or kernel proof.

Microsoft Filter Arbitration: lower sublayers can override soft decisions;
callout veto can override hard permit. This is a deliberately small boundary model.
"""
import hashlib, itertools, json

HIGH = ('soft_permit', 'hard_permit', 'soft_block', 'hard_block')
LOW = ('continue', 'permit', 'block', 'veto')

def decision(high, low):
    if high == 'hard_block':
        return 'BLOCK'
    if low == 'veto':
        return 'BLOCK'
    if high == 'hard_permit':
        return 'PERMIT'
    if low == 'continue':
        return 'PERMIT' if high == 'soft_permit' else 'BLOCK'
    return 'BLOCK' if low == 'block' else 'PERMIT'

def old_diagnostic(higher=0, equal=0, lower=0):
    return 3 if higher or equal else 4

def corrected_diagnostic(higher=0, equal=0, lower=0):
    return 3 if higher or equal or lower else 4

def main():
    cases = []
    for high, low in itertools.product(HIGH, LOW):
        verdict = decision(high, low)
        cases.append(f'{high},{low},{verdict}\n')
    assert decision('soft_permit', 'block') == 'BLOCK'
    assert decision('hard_permit', 'veto') == 'BLOCK'
    assert decision('hard_permit', 'block') == 'PERMIT'
    assert decision('hard_block', 'permit') == 'BLOCK'
    assert decision('soft_block', 'permit') == 'PERMIT'
    assert old_diagnostic(lower=1) == 4
    assert corrected_diagnostic(lower=1) == 3
    assert corrected_diagnostic() == 4
    digest = hashlib.sha256(''.join(cases).encode()).hexdigest()
    print(json.dumps({'cases':len(cases),'arbitration_matrix_sha256':digest,
          'counterexample':'higher soft_permit + lower block -> BLOCK',
          'hard_permit_veto':'BLOCK', 'old_lower_only_exit':4,
          'corrected_lower_only_exit':3},sort_keys=True))
if __name__ == '__main__':main()
