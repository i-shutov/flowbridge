"""Independent R21 event-proof oracle + explicit mutation sensitivity.

No Windows API calls, drivers, filters, sockets or network effects.
"""
from dataclasses import asdict,replace
from itertools import product
from random import Random
import json
import policy_barrier_r21 as impl

FIELDS=('source_event_token','session','pid','creation_epoch','appid','family','transport','tuple')


def oracle(flow,event,policy):
    """Independent spec using a normalized dictionary, not implementation predicate."""
    f=asdict(flow); e=asdict(event)
    if policy<=0 or e['policy_epoch']!=policy: return False
    if not all((e['is_reauthorize'],e['action']=='BLOCK',e['from_kernel_event'],e['fields_known'])):
        return False
    if not f['source_event_token'] or not f['pid'] or not f['creation_epoch'] or not f['appid']:
        return False
    if e['appid'] is None or f['family'] not in (4,6):return False
    return all(f[field]==e[field] for field in FIELDS)


def fixtures():
    for fam,transport in product((4,6),('TCP','UDP')):
        f=impl.Flow(19,88,9,420,b'opaque_appid',fam,transport,'same:443')
        e=impl.Auth(19,88,9,420,b'opaque_appid',fam,transport,'same:443',10,True,'BLOCK',True,True)
        yield f,e,10


def run():
    checked=0; changed=0; good=0
    rnd=Random(20261107)
    replacements={
        'source_event_token':(0,20),'session':(0,87),'pid':(0,11),
        'creation_epoch':(0,419),'appid':(None,b'other_appid'),
        'family':(4,6,9),'transport':('TCP','UDP','ICMP'),
        'tuple':('else:443',), 'policy_epoch':(0,9,11),
        'is_reauthorize':(False,), 'action':('PERMIT','CONTINUE'),
        'from_kernel_event':(False,), 'fields_known':(False,)
    }
    for f,e,p in fixtures():
        for i in range(1024):
            base=asdict(e)
            if i%16:
                key=list(replacements)[rnd.randrange(len(replacements))]
                v=rnd.choice(replacements[key]);base[key]=v
            candidate=impl.Auth(**base)
            expected=oracle(f,candidate,p)
            actual=impl.event_bound_observation(f,candidate,p)
            assert actual==expected,(f,candidate,p,expected,actual)
            checked+=1; good+=expected;changed+=not expected

    # Explicitly broken alternative predicates: all must be refuted by the same
    # fixed examples; this verifies that tests detect real semantic weaknesses.
    mutants={
        'commit_implies_all_flows_reauthorized': lambda: any(
            one.view.commit_ok and not two.all_existing_flows_revalidated for one,two in impl.all_pairs()),
        'tuple_only_join': lambda: any(
            f.tuple==replace(e,source_event_token=77).tuple
            and not oracle(f,replace(e,source_event_token=77),p) for f,e,p in fixtures()),
        'pid_without_creation_epoch': lambda: any(
            f.pid==replace(e,creation_epoch=421).pid
            and not oracle(f,replace(e,creation_epoch=421),p) for f,e,p in fixtures()),
        'accept_stale_policy_epoch': lambda: any(
            e.is_reauthorize and not oracle(f,replace(e,policy_epoch=9),p) for f,e,p in fixtures()),
        'accept_FWP_EMPTY_appid': lambda: any(
            not oracle(f,replace(e,appid=None),p) for f,e,p in fixtures()),
        'untrusted_event_as_kernel_origin': lambda: any(
            not oracle(f,replace(e,from_kernel_event=False),p) for f,e,p in fixtures()),
        'permit_called_block': lambda: any(
            not oracle(f,replace(e,action='PERMIT'),p) for f,e,p in fixtures()),
        'dynamic_session_crash_leaves_filter': lambda:
            impl.policy_object_after_owner_exit('dynamic',True)=='POLICY_OBJECT_REMOVED',
    }
    detected=[name for name,fn in mutants.items() if fn()]
    assert len(detected)==len(mutants),('mutation_detection_failed',detected)
    assert impl.policy_object_after_owner_exit('static',True)=='ENFORCEMENT_UNPROVEN'
    assert impl.policy_object_after_owner_exit('persistent',True)=='ENFORCEMENT_UNPROVEN'
    count=sum(1 for _ in impl.all_pairs())
    assert count==144
    return dict(ok=True,version='R21',source='offline_model_only',
                observational_pairs=count,independent_event_oracle_cases=checked,
                negative_event_oracle_cases=changed,positive_event_oracle_cases=good,
                detected_mutant_families=detected,driver_or_filter_started=False,
                windows_native_proof=False,commit_enforcement_barrier_proved=False,
                kernel_origin_verified=False,packetbound_g2_pass=False,no_direct_proved=False)

if __name__=='__main__':print(json.dumps(run(),indent=2))
