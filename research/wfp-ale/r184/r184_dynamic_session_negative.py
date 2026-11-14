"""R184: offline model of OWN WFP policy-object lifetime, NOT packet enforcement.

Microsoft contract: objects in FWPM_SESSION_FLAG_DYNAMIC are removed on owner
session termination. Source-fixed sublayer/filter GUIDs collide across overlapping
owners. All observations are synthetic; no Windows APIs, sockets or filtering.
"""
import itertools
import json
import sys

FAMILIES = ('v4', 'v6')
PROTOCOLS = ('tcp', 'udp')
ORIGINS = ('selected', 'sibling')
GUARDS = (False, True)  # independent unrelated provider; never ours
SCENARIOS = ('owner_exit', 'close_then_replace', 'fixed_key_overlap', 'distinct_key_overlap')


def event_trace(scenario):
    # Active sublayers are modelled as globally unique GUID keys. Replacing
    # dynamic BFE policy with an equivalent key requires the old owner to end.
    active = {'fixed': 'A'}
    trace = [('baseline', len(active))]
    collisions = 0
    if scenario == 'owner_exit':
        active = {k: v for k, v in active.items() if v != 'A'}
        trace.append(('owner_exit', len(active)))
    elif scenario == 'close_then_replace':
        active = {k: v for k, v in active.items() if v != 'A'}
        trace.append(('close_old', len(active)))
        active['fixed'] = 'B'
        trace.append(('commit_new', len(active)))
    elif scenario == 'fixed_key_overlap':
        if 'fixed' in active:
            collisions += 1  # New owning session cannot add same sublayer GUID
        else:
            active['fixed'] = 'B'
        trace.append(('stage_new_fixed', len(active)))
        active = {k: v for k, v in active.items() if v != 'A'}
        trace.append(('close_old', len(active)))
        active['fixed'] = 'B'
        trace.append(('retry_new', len(active)))
    elif scenario == 'distinct_key_overlap':
        # Contrast-only hypothetical new design; not a change to the real R19.
        active['new_unique_key'] = 'B'
        trace.append(('stage_unique', len(active)))
        active = {k: v for k, v in active.items() if v != 'A'}
        trace.append(('close_old', len(active)))
    else:
        raise ValueError(scenario)
    return trace, collisions


def row(family, protocol, origin, guard, scenario):
    trace, collisions = event_trace(scenario)
    owned = origin == 'selected' and protocol == 'tcp'
    cover = [owned and count > 0 for _, count in trace]
    return dict(family=family, protocol=protocol, origin=origin, external_blocker=guard,
                scenario=scenario, timeline='>'.join(f'{step}:{int(covered)}' for (step, _), covered in zip(trace, cover)),
                owned_gap=owned and not all(cover), collision=bool(collisions),
                # unrelated enforcement is deliberately not confused with ours:
                effective_result='UNKNOWN',
                alternative_guard_may_block=guard)


def matrix():
    return [row(*args) for args in itertools.product(FAMILIES, PROTOCOLS, ORIGINS, GUARDS, SCENARIOS)]


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'))


def test():
    rows = matrix()
    assert len(rows) == 64
    assert all(r['effective_result'] == 'UNKNOWN' for r in rows)
    selected_tcp = [r for r in rows if r['origin']=='selected' and r['protocol']=='tcp']
    assert len(selected_tcp)==16
    assert sum(r['owned_gap'] for r in selected_tcp)==12
    assert all(r['owned_gap'] for r in selected_tcp if r['scenario']!='distinct_key_overlap')
    assert all(not r['owned_gap'] for r in selected_tcp if r['scenario']=='distinct_key_overlap')
    assert sum(r['collision'] for r in rows)==16
    assert all(not r['owned_gap'] for r in rows if r['origin']=='sibling' or r['protocol']=='udp')
    assert all(r['alternative_guard_may_block']==r['external_blocker'] for r in rows)
    assert all(r['timeline'].startswith('baseline:') for r in rows)
    # A forbidden mutation of the Microsoft lifetime contract must be caught.
    assert event_trace('owner_exit')[0][-1] == ('owner_exit',0)
    assert event_trace('fixed_key_overlap')[0][1] == ('stage_new_fixed',1)
    assert event_trace('close_then_replace')[0][1] == ('close_old',0)
    assert event_trace('distinct_key_overlap')[0][-1] == ('close_old',1)
    return len(rows)

if __name__ == '__main__':
    if sys.argv[1:] == ['test']:
        print(f'{test()} cases: PASS')
    elif not sys.argv[1:]:
        test()
        for r in matrix(): print(canonical(r))
    else:
        raise SystemExit('usage: python r184_dynamic_session_negative.py [test]')
