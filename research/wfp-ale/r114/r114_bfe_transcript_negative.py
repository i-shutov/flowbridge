#!/usr/bin/env python3
"""R114: independent deterministic transcript contract model, no Windows/WFP calls.
The compiler/PowerShell harness MUST still be validated on authorized Windows 5.1.
"""
from __future__ import annotations
import hashlib
import itertools
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parent
SCRIPT=ROOT.parent/'r112'/'R112_WINDOWS_NATIVE_READONLY_CHECK.ps1'
if not SCRIPT.exists(): SCRIPT=ROOT/'R112_WINDOWS_NATIVE_READONLY_CHECK.ps1'
LABELS=('auth_connect_v4','auth_connect_v6','connect_redirect_v4','connect_redirect_v6')
FIELDS=('visible_higher','visible_equal','visible_lower','visible_disabled')
GOOD_STATUS=('VISIBLE_ARBITRATION_CANDIDATE','UNKNOWN_NO_VISIBLE_CANDIDATE')
MAX_VISIBLE=131072


def exact_int(v): return type(v) is int and 0<=v<=MAX_VISIBLE

def check(rc:int,rows:list[dict])->tuple[str,int]:
    failed=('UNAVAILABLE_OR_FAILED',2)
    if rc not in (3,4) or len(rows)!=5: return failed
    candidate=False; total_foreign=0
    for i, label in enumerate(LABELS):
        row=rows[i]
        if not isinstance(row,dict) or type(row.get('rule')) is not str or row['rule']!=label or row.get('match_and_runtime_action_unverified') is not True: return failed
        for key in FIELDS:
            x=row.get(key)
            if not exact_int(x): return failed
            total_foreign+=x
        candidate |= row['visible_higher']>0 or row['visible_equal']>0
    tail=rows[-1]
    if not isinstance(tail,dict): return failed
    v=tail.get('visible_filters')
    if not exact_int(v) or v<4 or total_foreign>v-4: return failed
    for key,expected in (('single_enum_snapshot',True),('acl_hidden_filters_possible',True),('kernel_proof',False),('no_direct_proof',False)):
        if type(tail.get(key)) is not bool or tail[key] is not expected: return failed
    expected_status=GOOD_STATUS[0 if candidate else 1]
    expected_rc=3 if candidate else 4
    if type(tail.get('status')) is not str or tail['status']!=expected_status or rc!=expected_rc: return failed
    return ('BFE_VISIBLE_ARBITRATION_CANDIDATE_NO_KERNEL_PROOF' if candidate else 'BFE_UNKNOWN_NO_VISIBLE_CANDIDATE', expected_rc)


def rows_for(hi:int,eq:int,boolean_type:str,counter_type:str,visible_type:str)->list[dict]:
    rows=[dict(rule=name,visible_higher=hi if i==0 else 0, visible_equal=eq if i==1 else 0, visible_lower=0, visible_disabled=0,match_and_runtime_action_unverified=True) for i,name in enumerate(LABELS)]
    candidate=hi>0 or eq>0
    tail=dict(status=GOOD_STATUS[0 if candidate else 1],single_enum_snapshot=True,acl_hidden_filters_possible=True,kernel_proof=False,no_direct_proof=False,visible_filters=4+hi+eq)
    if boolean_type=='numeric': tail['kernel_proof']=0;rows[0]['match_and_runtime_action_unverified']=1
    elif boolean_type=='strings':tail['single_enum_snapshot']='true';rows[0]['match_and_runtime_action_unverified']='true'
    if counter_type=='fraction':rows[0]['visible_higher']=float(hi)+0.5
    elif counter_type=='boolean':rows[0]['visible_higher']=True
    elif counter_type=='negative':rows[0]['visible_lower']=-1
    elif counter_type=='overbudget':rows[0]['visible_lower']=MAX_VISIBLE+1
    if visible_type=='too_small':tail['visible_filters']=4+hi+eq-1
    elif visible_type=='missing':del tail['visible_filters']
    elif visible_type=='boolean':tail['visible_filters']=True
    elif visible_type=='overbudget':tail['visible_filters']=MAX_VISIBLE+1
    return rows+[tail]


def matrix()->list[dict]:
    out=[]
    for rc,hi,eq,bt,ct,vt in itertools.product(range(6), (0,1),(0,1), ('valid','numeric','strings'), ('valid','fraction','boolean','negative','overbudget'),('valid','too_small','missing','boolean','overbudget')):
        rows=rows_for(hi,eq,bt,ct,vt)
        status,code=check(rc,rows)
        out.append(dict(case=f'{rc}:{hi}:{eq}:{bt}:{ct}:{vt}',status=status,exit_code=code))
    return out

class R114Tests(unittest.TestCase):
    def test_only_valid_snapshot_nonzero_diagnostic(self):
        for rc,hi,eq in itertools.product(range(6),(0,1),(0,1)):
            rows=rows_for(hi,eq,'valid','valid','valid')
            expect=3 if hi or eq else 4
            status,code=check(rc,rows)
            if rc==expect: self.assertEqual(code,expect)
            else:self.assertEqual((status,code),('UNAVAILABLE_OR_FAILED',2))
    def test_128bit_like_and_uint64_unreasonable_fields_rejected(self):
        for bad in (-1,MAX_VISIBLE+1,2**64-1,float('inf'),True,1.5,'1'):
            rows=rows_for(1,0,'valid','valid','valid');rows[1]['visible_lower']=bad
            self.assertEqual(check(3,rows)[1],2)
    def test_old_r113_accepted_inconsistent_cardinality_in_model(self):
        rows=rows_for(1,0,'valid','valid','too_small')
        self.assertEqual(rows[-1]['visible_filters'],4)
        self.assertEqual(check(3,rows),('UNAVAILABLE_OR_FAILED',2))
        # R113 implementation only checks four rows and terminal flags;
        # its text has no read of the terminal visible_filters member.
        old_path=ROOT.parent/'r113'/'r113_bfe_exit_negative.py'
        if not old_path.exists(): old_path=ROOT/'r113_bfe_exit_negative.py'
        old=old_path.read_text()
        self.assertNotIn("tail.get('visible_filters')",old)
        self.assertNotIn("rows[-1]['visible_filters']",old)
        from importlib.util import module_from_spec,spec_from_file_location
        spec=spec_from_file_location('prior_r113',old_path)
        prior=module_from_spec(spec);spec.loader.exec_module(prior)
        self.assertEqual(prior.verdict(3,rows),('BFE_VISIBLE_ARBITRATION_CANDIDATE_NO_KERNEL_PROOF',3))
    def test_all_bad_types_and_insufficient_counts(self):
        for rc in (3,4):
            for bo,co,vi in itertools.product(('valid','numeric','strings'),('valid','fraction','boolean','negative','overbudget'),('valid','too_small','missing','boolean','overbudget')):
                if (bo,co,vi)==('valid','valid','valid'):continue
                self.assertEqual(check(rc,rows_for(1,0,bo,co,vi))[1],2)
    def test_ps_script_contains_actual_strict_gates(self):
        s=SCRIPT.read_text()
        self.assertIn('$totalForeign += [long]$value',s)
        self.assertIn('$totalForeign -gt ([long]$terminal.visible_filters - 4)',s)
        self.assertIn('$terminal.visible_filters -gt 131072',s)
        self.assertIn('$item.match_and_runtime_action_unverified -isnot [bool]',s)
        self.assertIn('$terminal.$flag -isnot [bool]',s)
        self.assertIn('($value -isnot [int] -and $value -isnot [long])',s)
        self.assertNotIn('$value -isnot [ValueType]',s)
        self.assertIn('$exitStatus = $expectedExit',s)
        for forbidden in ('FwpmFilterAdd0','FwpmFilterDeleteByKey0','FwpmCalloutAdd0','New-NetFirewallRule','Set-NetFirewallProfile','Install-Module','winget install','Start-Service','New-Service'):
            self.assertNotIn(forbidden,s)
    def test_matrix_has_rejections_and_justified_diagnostics(self):
        data=matrix()
        self.assertEqual(len(data),1800)
        self.assertTrue(all(x['exit_code'] in (2,3,4) for x in data))
        self.assertGreater(sum(x['exit_code']==2 for x in data),1700)
        self.assertGreater(sum(x['exit_code']==3 for x in data),0)
        self.assertGreater(sum(x['exit_code']==4 for x in data),0)
    def test_documented_scope_is_no_kernel_proof(self):
        self.assertFalse(any('KERNEL_PROOF'==x['status'] for x in matrix()))

if __name__=='__main__':
    if '--matrix' in sys.argv:
        data=matrix()
        serialized=''.join(json.dumps(r,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n' for r in data)
        print(json.dumps(dict(cases=len(data),sha256=hashlib.sha256(serialized.encode()).hexdigest(),statuses={k:sum(r['status']==k for r in data) for k in sorted({r['status'] for r in data})}),sort_keys=True))
    else:unittest.main(verbosity=2)
