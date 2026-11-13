#!/usr/bin/env python3
"""R160 bounded negative model: absence of R19 filters != observed packet leak."""
import itertools, json, subprocess, sys, unittest
EVENTS=('BFE_SESSION_LOST','BFE_SERVICE_RESTART','HEARTBEAT','PROBE',
        'SELECTED_V4','SELECTED_V6','SSH_LOST','BROKER_EXIT')
PINS={'broker.rs':'6163e84aea08ddde7e51a7fb94ccb6d68ae951fb',
      'policy_windows.rs':'acf60334320d970f58af3349ee75fbaa59826602',
      'policy_plan.rs':'0c3d0e88eb9d06f4030131d9533da2d629dbdab0',
      'broker_windows.rs':'329ef14b63e70226bfad7372b0014559213abd04'}

def source_gate():
    src={}
    for name,pin in PINS.items():
        path='research/wfp-ale/kernel-r19/'+name
        sha=subprocess.check_output(['git','rev-parse','HEAD:'+path],text=True).strip()
        if sha!=pin: raise AssertionError((name,sha,pin))
        src[name]=subprocess.check_output(['git','show','HEAD:'+path]).decode()
    b,p,w=src['broker.rs'],src['policy_windows.rs'],src['broker_windows.rs']
    if not b.index('policy_windows::Installed::activate_admitted(&plan)')<b.index('device.arm(&selection,&plan,ports[0],ports[1])')<b.index('let heartbeat='):
        raise ValueError('BFE ARM heartbeat ordering changed')
    heartbeat=b.split('let heartbeat=',1)[1].split('// Native lab admission',1)[0]
    if 'd.command(handoff::PING,&[])' not in heartbeat: raise ValueError('kernel heartbeat missing')
    if 'FwpmFilterGetByKey0' in heartbeat or 'policy.' in heartbeat: raise ValueError('BFE heartbeat architecture changed')
    if 'FWPM_SESSION_FLAG_DYNAMIC' not in p or 'FwpmFilterGetByKey0' not in p: raise ValueError('policy lifetime/readback changed')
    if 'plan.arm_matches(image.wfp_appid(),[port4,port6])' not in w: raise ValueError('ARM guard missing')
    return True

def simulate(events):
    # State immediately after successful R159 readback and ARM.
    s={'bfe':True,'filters':True,'lease':True,'broker':True,'reported':True,
       'v4':0,'v6':0,'unrevoked_uncovered':0,'probed':False}
    for event in events:
        if event=='BFE_SESSION_LOST':s['bfe']=False;s['filters']=False
        elif event=='BFE_SERVICE_RESTART':s['bfe']=True # filters not automatically restored
        elif event=='HEARTBEAT':s['reported']=s['lease'] and s['broker'] # no BFE readback
        elif event=='PROBE':
            s['probed']=True
            if not s['filters']:s['lease']=False;s['reported']=False
        elif event in ('SELECTED_V4','SELECTED_V6'):
            if not s['filters']:
                s['v4' if event=='SELECTED_V4' else 'v6']+=1
                s['unrevoked_uncovered']+=int(s['reported'])
        elif event=='SSH_LOST':s['lease']=False;s['reported']=False
        elif event=='BROKER_EXIT':s['broker']=False;s['filters']=False;s['lease']=False;s['reported']=False
        else:raise ValueError(event)
    return s

def matrix():
    c=dict(traces=0,uncovered_v4_traces=0,uncovered_v6_traces=0,
           uncovered_while_reported_traces=0,bfe_missing_reported_traces=0,
           probe_with_uncovered_traces=0)
    for n in range(5):
        for events in itertools.product(EVENTS,repeat=n):
            s=simulate(events);c['traces']+=1
            c['uncovered_v4_traces']+=bool(s['v4'])
            c['uncovered_v6_traces']+=bool(s['v6'])
            c['uncovered_while_reported_traces']+=bool(s['unrevoked_uncovered'])
            c['bfe_missing_reported_traces']+=not s['filters'] and s['reported']
            c['probe_with_uncovered_traces']+=s['probed'] and bool(s['v4']+s['v6'])
    return c

class Negative(unittest.TestCase):
    def test_ping_cannot_infer_bfe_session(self):
        s=simulate(('BFE_SESSION_LOST','HEARTBEAT'))
        self.assertTrue(s['lease'] and s['reported'] and not s['filters'])
    def test_two_families(self):
        s=simulate(('BFE_SESSION_LOST','SELECTED_V4','SELECTED_V6'))
        self.assertEqual((s['v4'],s['v6']),(1,1))
    def test_restart_cannot_recreate_dynamic_objects(self):
        self.assertFalse(simulate(('BFE_SESSION_LOST','BFE_SERVICE_RESTART'))['filters'])
    def test_optimistic_monitor_cannot_enforce_after_filter_loss(self):
        s=simulate(('BFE_SESSION_LOST','PROBE','SELECTED_V4'))
        self.assertFalse(s['lease']);self.assertEqual(s['v4'],1)
    def test_broker_death_removes_dynamic_filters(self):
        self.assertFalse(simulate(('BROKER_EXIT',))['filters'])
    def test_scope_not_wire_observation(self):
        self.assertNotIn('leak_proven',simulate(('BFE_SESSION_LOST','SELECTED_V4')))
    def test_bounded_total(self):self.assertEqual(matrix()['traces'],4681)
    def test_source_gate_must_not_vanish_under_optimization(self):
        import inspect
        self.assertNotIn('assert ', inspect.getsource(source_gate))

if __name__=='__main__':
    if sys.argv[1:]==['--matrix']:print(json.dumps(matrix(),sort_keys=True));sys.exit(0)
    if sys.argv[1:]==['--source-gate']:print(json.dumps({'exact_blobs':PINS,'pass':source_gate()},sort_keys=True));sys.exit(0)
    if sys.argv[1:]==['--test']:unittest.main(argv=[sys.argv[0]],verbosity=2);sys.exit(0)
    sys.exit('Usage: --matrix | --test | --source-gate (on exact branch checkout)')
