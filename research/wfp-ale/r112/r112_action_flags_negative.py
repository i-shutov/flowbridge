#!/usr/bin/env python3
"""Pure Python exhaustive oracle for documented 32-bit WFP action values.
No Windows APIs, drivers, filters, network operations, or runtime claims.
"""
import ctypes as ct
from hashlib import sha256
from itertools import product
from pathlib import Path
import json
import sys
import unittest

HERE = Path(__file__).resolve().parent
# Windows fwptypes.h: 0x4000 CALLOUT; 0x1000 TERMINATING; lower ordinals 3/5.
CALLOUT_TERMINATING = 0x4000 | 0x1000 | 3
CALLOUT_UNKNOWN = 0x4000 | 5
ACTIONS = (CALLOUT_TERMINATING, CALLOUT_UNKNOWN, 3, 5, 0x1002, 0x1001, 0x6004, 0x5004, 0x4003)
FLAGS = (0, 0x40, 0x20)  # accepted own flags: NONE and INDEXED; DISABLED invalid
APPS = tuple(range(13)) # structural AppId representations: 0,8,9 valid
TCPS = tuple(range(8))  # structural protocol representations: 0,5 valid
CALLOUT = tuple(range(3)) # 0=matching keyed callout, 1=wrong, 2=missing/unknown
RULES = tuple(range(4)) # AUTH v4/v6, REDIRECT v4/v6

def decision(rule:int,flag:int,action:int,callout:int,app:int,tcp:int)->str:
    if flag not in (0,0x40): return 'UNKNOWN_FLAGS'
    expected = CALLOUT_TERMINATING if rule < 2 else CALLOUT_UNKNOWN
    if action != expected or callout != 0: return 'UNKNOWN_ACTION_OR_CALLOUT'
    if app not in (0,8,9): return 'UNKNOWN_APP_ID'
    if tcp not in (0,5): return 'UNKNOWN_TCP'
    return 'STRUCTURAL_ONLY'

def table()->dict:
    h = sha256()
    categories = {}
    cases = old_visible = structural = wrong_old_baselines = bare_action_rejected = 0
    for rule, flag, action, callout, app, tcp in product(RULES, FLAGS, ACTIONS, CALLOUT, APPS, TCPS):
        old = 'BASELINE_VISIBLE' if flag in (0,0x40) else 'UNKNOWN_FLAGS'
        new = decision(rule, flag, action, callout, app, tcp)
        h.update(f'{rule}|{flag}|{action}|{callout}|{app}|{tcp}|{old}|{new}\n'.encode())
        cases += 1
        old_visible += old == 'BASELINE_VISIBLE'
        structural += new == 'STRUCTURAL_ONLY'
        wrong_old_baselines += old == 'BASELINE_VISIBLE' and new != 'STRUCTURAL_ONLY'
        bare_action_rejected += action in (3,5) and new != 'STRUCTURAL_ONLY'
        categories[new] = categories.get(new,0)+1
    return dict(cases=cases,old_visible=old_visible,structural_only=structural,
                old_overclaims=wrong_old_baselines,bare_action_rejected=bare_action_rejected,
                classes=categories,sha256=h.hexdigest(),windows_run=False,kernel_proof=False)

class Guid(ct.Structure):
    _fields_=[('d1',ct.c_uint32),('d2',ct.c_uint16),('d3',ct.c_uint16),('d4',ct.c_uint8*8)]
class Blob(ct.Structure):
    _fields_=[('len',ct.c_uint32),('data',ct.c_void_p)]
class Value(ct.Structure):
    _fields_=[('kind',ct.c_uint32),('pad',ct.c_uint32),('bits',ct.c_uint64)]
class Cond(ct.Structure):
    _fields_=[('key',Guid),('op',ct.c_uint32),('val',Value)]
class Action(ct.Structure):
    _fields_=[('kind',ct.c_uint32),('key',Guid)]
class Display(ct.Structure):
    _fields_=[('name',ct.c_void_p),('description',ct.c_void_p)]
class Filter(ct.Structure):
    _fields_=[('key',Guid),('display',Display),('flags',ct.c_uint32),('provider',ct.c_void_p),
              ('provider_data',Blob),('layer',Guid),('sublayer',Guid),('weight',Value),
              ('num_conditions',ct.c_uint32),('conditions',ct.c_void_p),('action',Action),
              ('context',ct.c_uint64*2),('reserved',ct.c_void_p),('filter_id',ct.c_uint64),
              ('effective_weight',Value)]

class WfpActionChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.source=(HERE/'r103_readonly_arbitration_inventory.rs').read_text()
    def test_actual_wfp_action_constants(self):
        self.assertEqual(CALLOUT_TERMINATING,0x5003)
        self.assertEqual(CALLOUT_UNKNOWN,0x4005)
        self.assertNotEqual(CALLOUT_TERMINATING,3)
        self.assertNotEqual(CALLOUT_UNKNOWN,5)
    def test_rust_constants_exact(self):
        self.assertIn('const FWP_ACTION_CALLOUT_TERMINATING:u32=0x00005003;',self.source)
        self.assertIn('const FWP_ACTION_CALLOUT_UNKNOWN:u32=0x00004005;',self.source)
        self.assertNotIn('FWP_ACTION_CALLOUT_TERMINATING:u32=3;',self.source)
        self.assertNotIn('FWP_ACTION_CALLOUT_UNKNOWN:u32=5;',self.source)
    def test_real_action_accepts_wrong_flags_deny(self):
        for r in RULES:
            expected=CALLOUT_TERMINATING if r<2 else CALLOUT_UNKNOWN
            self.assertEqual(decision(r,0,expected,0,0,0),'STRUCTURAL_ONLY')
            for invalid in (3,5,0x1002,0x6004,0x5004,0x4003):
                self.assertNotEqual(decision(r,0,invalid,0,0,0),'STRUCTURAL_ONLY')
    def test_wrong_or_missing_callout_deny(self):
        for r in RULES:
            expected=CALLOUT_TERMINATING if r<2 else CALLOUT_UNKNOWN
            for wrong in (1,2):
                self.assertEqual(decision(r,0,expected,wrong,0,0),'UNKNOWN_ACTION_OR_CALLOUT')
    def test_disabled_base_deny(self):
        for r in RULES:
            expected=CALLOUT_TERMINATING if r<2 else CALLOUT_UNKNOWN
            self.assertEqual(decision(r,0x20,expected,0,0,0),'UNKNOWN_FLAGS')
            self.assertEqual(decision(r,0x40,expected,0,0,0),'STRUCTURAL_ONLY')
    def test_malformed_appid_and_tcp_deny(self):
        for r in RULES:
            expected=CALLOUT_TERMINATING if r<2 else CALLOUT_UNKNOWN
            for app in set(APPS) - {0,8,9}:
                self.assertEqual(decision(r,0,expected,0,app,0),'UNKNOWN_APP_ID')
            for proto in set(TCPS) - {0,5}:
                self.assertEqual(decision(r,0,expected,0,0,proto),'UNKNOWN_TCP')
    def test_ffi_layout_opaque_x64_model(self):
        self.assertEqual((ct.sizeof(Cond),Cond.val.offset),(40,24))
        self.assertEqual((ct.sizeof(Filter),Filter.action.offset,Filter.filter_id.offset,
                          Filter.effective_weight.offset),(200,128,176,184))
    def test_readonly_source_only(self):
        for forbidden in ('FwpmFilterAdd0','FwpmCalloutAdd0','FwpmSubLayerAdd0',
                          'FwpmFilterDeleteByKey0','FwpmEngineSetOption0',
                          'FwpmTransactionBegin0','Command::new','std::net::'):
            self.assertNotIn(forbidden,self.source)
        for must in ('fn owned_policy_shape(', 'baseline_cross_family_appid_mismatch',
                     'f.action.kind!=expected_action || f.action.key!=CALLOUTS[i]',
                     'fn owned_shape_synthetic_mutants()'):
            self.assertIn(must,self.source)
    def test_matrix_consistency(self):
        out=table()
        self.assertEqual(out['cases'],4*3*9*3*13*8)
        self.assertEqual(out['structural_only'],4*2*1*1*3*2)
        self.assertEqual(sum(out['classes'].values()),out['cases'])
        self.assertFalse(out['kernel_proof'])

if __name__=='__main__':
    result = unittest.main(exit=False,verbosity=2)
    if not result.result.wasSuccessful(): sys.exit(1)
    print('R112_WFP_ACTION_ORACLE='+json.dumps(table(),sort_keys=True))
