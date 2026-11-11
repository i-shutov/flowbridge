#!/usr/bin/env python3
"""R113: executable off-host negative model for Windows BFE inspector exit semantics.
No Windows APIs, driver, network, WFP or CI. Not a replacement for a PS5.1 run.
"""
from __future__ import annotations
import hashlib
import itertools
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SCRIPT = (ROOT / 'R112_WINDOWS_NATIVE_READONLY_CHECK.ps1')
if not SCRIPT.exists():
    SCRIPT = ROOT.parent / 'r112' / 'R112_WINDOWS_NATIVE_READONLY_CHECK.ps1'
LABELS = ('auth_connect_v4','auth_connect_v6','connect_redirect_v4','connect_redirect_v6')
STATUS = ('VISIBLE_ARBITRATION_CANDIDATE','UNKNOWN_NO_VISIBLE_CANDIDATE','UNKNOWN')


def verdict(rc: int, rows: list[dict]) -> tuple[str,int]:
    if rc not in (3,4):
        return ('UNAVAILABLE_OR_FAILED',2)
    if len(rows)!=5:
        return ('UNAVAILABLE_OR_FAILED',2)
    candidate=False
    for i,label in enumerate(LABELS):
        row=rows[i]
        if row.get('rule')!=label or row.get('match_and_runtime_action_unverified') is not True:
            return ('UNAVAILABLE_OR_FAILED',2)
        for field in ('visible_higher','visible_equal','visible_lower','visible_disabled'):
            if type(row.get(field)) is not int or row[field]<0:
                return ('UNAVAILABLE_OR_FAILED',2)
        candidate |= row['visible_higher']>0 or row['visible_equal']>0
    tail=rows[-1]
    want='VISIBLE_ARBITRATION_CANDIDATE' if candidate else 'UNKNOWN_NO_VISIBLE_CANDIDATE'
    want_rc=3 if candidate else 4
    if (rc!=want_rc or tail.get('status')!=want or
        tail.get('single_enum_snapshot') is not True or
        tail.get('acl_hidden_filters_possible') is not True or
        tail.get('kernel_proof') is not False or
        tail.get('no_direct_proof') is not False):
        return ('UNAVAILABLE_OR_FAILED',2)
    return ('BFE_VISIBLE_ARBITRATION_CANDIDATE_NO_KERNEL_PROOF' if candidate
            else 'BFE_UNKNOWN_NO_VISIBLE_CANDIDATE',want_rc)


def make_rows(hi:int,eq:int,terminal:str,proof:bool) -> list[dict]:
    rows=[dict(rule=label,visible_higher=hi if i==0 else 0,
          visible_equal=eq if i==1 else 0,visible_lower=0,visible_disabled=0,
          match_and_runtime_action_unverified=True)
          for i,label in enumerate(LABELS)]
    rows.append(dict(status=terminal,single_enum_snapshot=True,
                     acl_hidden_filters_possible=True,kernel_proof=proof,
                     no_direct_proof=False,visible_filters=4))
    return rows


def matrix() -> list[dict]:
    cases=[]
    for rc,hi,eq,terminal,proof in itertools.product(
        range(6),(0,1),(0,1),STATUS,(False,True)):
        name=f'{rc}:{hi}:{eq}:{terminal}:{int(proof)}'
        state,exit_code=verdict(rc,make_rows(hi,eq,terminal,proof))
        cases.append(dict(case=name,status=state,exit_code=exit_code))
    for mutation in ('missing_row','wrong_rule','missing_counter','negative_counter',
                     'proof_claimed','hidden_acl_false','nonbool_counter',
                     'duplicated_rule','missing_terminal','no_direct_true'):
        rows=make_rows(1,0,'VISIBLE_ARBITRATION_CANDIDATE',False)
        if mutation=='missing_row': rows.pop(0)
        elif mutation=='wrong_rule': rows[2]['rule']='connect_redirect_v7'
        elif mutation=='missing_counter': del rows[1]['visible_higher']
        elif mutation=='negative_counter': rows[0]['visible_lower']=-3
        elif mutation=='proof_claimed': rows[4]['kernel_proof']=True
        elif mutation=='hidden_acl_false': rows[4]['acl_hidden_filters_possible']=False
        elif mutation=='nonbool_counter': rows[0]['visible_lower']=False
        elif mutation=='duplicated_rule': rows[0]['rule']=rows[1]['rule']
        elif mutation=='missing_terminal': rows.pop()
        elif mutation=='no_direct_true': rows[4]['no_direct_proof']=True
        status,code=verdict(3,rows)
        cases.append(dict(case='mutation:'+mutation,status=status,exit_code=code))
    return cases


class R113Tests(unittest.TestCase):
    def test_native_contract_no_success_for_live_bfe(self):
        for item in matrix():
            self.assertNotEqual(item['exit_code'],0)

    def test_only_candidate_or_unknown_nonzero(self):
        self.assertEqual(verdict(3,make_rows(1,0,STATUS[0],False)),
                         ('BFE_VISIBLE_ARBITRATION_CANDIDATE_NO_KERNEL_PROOF',3))
        self.assertEqual(verdict(4,make_rows(0,0,STATUS[1],False)),
                         ('BFE_UNKNOWN_NO_VISIBLE_CANDIDATE',4))
        self.assertEqual(verdict(2,make_rows(1,0,STATUS[0],False)),
                         ('UNAVAILABLE_OR_FAILED',2))

    def test_live_bfe_failure_was_mislabeled_as_success_in_r112(self):
        source=(ROOT/'R112_FALSE_SUCCESS_EXCERPT.txt').read_text()
        self.assertIn("$report.bfe_inventory_exit_code = $inventory.ExitCode",source)
        self.assertIn("$report.status = 'BFE_READONLY_MANAGEMENT_SNAPSHOT_NO_KERNEL_PROOF'",source)
        self.assertIn("$exitStatus = 0\n        }",source)

    def test_fixed_script_rejects_known_unknown_and_unexpected_codes(self):
        src=SCRIPT.read_text()
        self.assertIn('if ($inventory.ExitCode -eq 2)',src)
        self.assertIn('if ($inventory.ExitCode -ne 3 -and $inventory.ExitCode -ne 4)',src)
        self.assertIn('$exitStatus = $expectedExit',src)
        self.assertIn("$terminal.kernel_proof -cne $false",src)
        self.assertIn("$terminal.no_direct_proof -cne $false",src)
        self.assertIn("$terminal.acl_hidden_filters_possible -cne $true",src)
        self.assertNotIn("$report.status = 'BFE_READONLY_MANAGEMENT_SNAPSHOT_NO_KERNEL_PROOF'",src)

    def test_same_exact_source_blob_and_no_system_mutation(self):
        src=SCRIPT.read_text()
        self.assertIn("$expectedGitBlob = '49506ca07145c18947a0845f2a1a63b3de1f54ec'",src)
        self.assertIn('if ($RunReadOnlyBfe -and -not $RunUnitTests)',src)
        self.assertIn('if ($RunReadOnlyBfe) {',src)
        for forbidden in ('FwpmFilterAdd0','FwpmFilterDeleteByKey0','FwpmCalloutAdd0',
                          'New-NetFirewallRule','Set-NetFirewallProfile','Disable-WindowsOptionalFeature',
                          'Install-Module','winget install','Start-Service','New-Service'):
            self.assertNotIn(forbidden,src)

    def test_malformed_terminal_never_becomes_candidate(self):
        for mutation in matrix()[-10:]:
            self.assertEqual(mutation['status'],'UNAVAILABLE_OR_FAILED')
            self.assertEqual(mutation['exit_code'],2)

    def test_offhost_build_has_no_windows_proof(self):
        self.assertFalse(any('WINDOWS_RUST_TESTS_PASS' in x['status'] for x in matrix()))


if __name__=='__main__':
    import sys
    if '--matrix' in sys.argv:
        data=matrix(); serialized=''.join(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n'
                                 for row in data)
        print(json.dumps(dict(cases=len(data),sha256=hashlib.sha256(serialized.encode()).hexdigest(),
            statuses={x:sum(v['status']==x for v in data) for x in sorted({v['status'] for v in data})}),sort_keys=True))
    else:
        unittest.main(verbosity=2)
