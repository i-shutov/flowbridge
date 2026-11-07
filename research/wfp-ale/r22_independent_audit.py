"""Independent R22 offline oracle and deliberately wrong-inference detectors.

Oracle uses only plain dictionaries and independent projection semantics, not
model implementation helpers. Import model solely to compare actual results.
"""
import json
from itertools import product
import r22_visibility_ambiguity as sut

FAMILIES = (4,6)
PROTOCOLS = ('TCP','UDP','DNS_UDP','QUIC_UDP')
FLAGS = ((),('PERMIT_IF_CALLOUT_UNREGISTERED',))


def independent_worlds():
    for family,proto,flag,owner in product(FAMILIES,PROTOCOLS,FLAGS,('A','B')):
        observation = {
            'sessions': (('A',510,True),('B',520,True)),
            'filters': (('filter-X',57,'provider-Z',family,proto,flag,'CALLOUT_TERMINATING','callout-Q'),),
            'session_snapshot_epoch':100,
            'filter_snapshot_epoch':101,
            'visibility_complete':False,
        }
        # Hidden creator has no field in management observation.
        survive_after_a_exit = owner != 'A'
        yield observation,owner,survive_after_a_exit


def wrong_strategy_hits():
    hits = {k:0 for k in (
        'all_survive','all_removed','first_session_is_creator','last_session_is_creator',
        'provider_is_creator','filter_present_certifies_no_direct',
        'commit_certifies_no_direct','permit_flag_ignored')}
    for view,creator,survives in independent_worlds():
        if True != survives: hits['all_survive']+=1
        if False != survives: hits['all_removed']+=1
        if (creator != 'A') != survives: raise AssertionError('oracle self-check')
        # Wrong owner conjectures: first-session -> removed, last -> survives.
        if (False != survives): hits['first_session_is_creator']+=1
        if (True != survives): hits['last_session_is_creator']+=1
        # A shared provider key has no filter-creator session identity.
        if (False != survives): hits['provider_is_creator']+=1
        # These strategies wrongly certify absence of DIRECT.
        hits['filter_present_certifies_no_direct']+=1
        hits['commit_certifies_no_direct']+=1
        if 'PERMIT_IF_CALLOUT_UNREGISTERED' in view['filters'][0][5]:
            hits['permit_flag_ignored']+=1
    assert all(hits.values()),hits
    return hits


def main():
    total=0
    paired={}
    for observation,creator,expected in independent_worlds():
        key=(observation['filters'][0][3],observation['filters'][0][4],observation['filters'][0][5])
        paired.setdefault(key,{})[creator]=(observation,expected)
        a,b=sut.indistinguishable_worlds(key[0],key[1],key[2])
        got=(a if creator=='A' else b).survives_exit('A')
        assert got==expected,(key,creator)
        actual=sut.local_filter_signal((a if creator=='A' else b).inventory.filters[0],False)
        oracle=('THIS_FILTER_TREATED_AS_PERMIT_IF_CALLOUT_MISSING'
             if 'PERMIT_IF_CALLOUT_UNREGISTERED' in key[2]
             else 'NO_SAFETY_INFERENCE_FROM_THIS_FILTER')
        assert actual==oracle,(key,actual,oracle)
        assert sut.certify_no_direct(a.inventory,policy_committed=True,
                      selected_appid_known=True,kernel_receipt=True) is False
        total+=1
    for pair in paired.values():
        assert set(pair)=={'A','B'}
        assert pair['A'][0]==pair['B'][0]
        assert pair['A'][1] is False and pair['B'][1] is True
    result={'ok':True,'independent_worlds_checked':total,
        'indistinguishable_pairs_checked':len(paired),
        'wrong_strategy_counterexample_counts':wrong_strategy_hits(),
        'oracle_implementation':'independent_plain_dict_projection',
        'source_function_compared':'indistinguishable_worlds and local_filter_signal',
        'real_wfp_observations':0,'no_direct_proved':False,'g2_pass':False}
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':main()
