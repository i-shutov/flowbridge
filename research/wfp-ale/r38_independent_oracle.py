#!/usr/bin/env python3
"""R38 independent truth-table audit, not importing the R38 model under test."""
import itertools

def audit():
    violations=[]; healthy=0; excluded=0
    # Independent declarative formula for expected worker behavior, not a
    # second copy of model class. Stages are explicitly hypothetical.
    for family,claimed,host_ok,channel_ok,heartbeat_ok,stop,ssh_ok,age in itertools.product(
            (4,6),(False,True),(False,True),(False,True),
            (False,True),(False,True),(False,True),(0,59_999,60_000)):
        payload_ready=claimed and host_ok and channel_ok
        observed_copy=payload_ready and ssh_ok and age<60_000
        safety_required=payload_ready and heartbeat_ok and (not stop) and ssh_ok and age<60_000
        if observed_copy and not safety_required:
            violations.append((family,claimed,host_ok,channel_ok,heartbeat_ok,stop,ssh_ok,age))
        elif observed_copy and safety_required: healthy+=1
        else: excluded+=1
    assert len(violations)>0
    assert any(row[4] is False and row[5] is True and row[7]==59_999 for row in violations)
    assert not any(row[2] is False or row[3] is False or row[1] is False for row in violations)
    assert not any(row[7]==60_000 for row in violations)
    total=len(violations)+healthy+excluded
    assert total==2*2**6*3
    return total,len(violations),healthy,excluded

if __name__=='__main__':
    total,violations,healthy,excluded=audit()
    print(f'R38 independent exhaustive truth table: {total} cases; {violations} modeled stale-copy windows; {healthy} healthy copies; {excluded} no-copy; PASS')
