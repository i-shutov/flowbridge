#!/usr/bin/env python3
"""Offline acceptance and negative controls. Never invokes WFP or Windows APIs."""
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('oracle', ROOT/'r139_receipt_oracle.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
EXPECTED='b96761c1db4c04d8e3485730b6c2c385cf6968af17eedc4edad4a39f7da9eb96'

class R139(unittest.TestCase):
    def test_11_gates(self): self.assertEqual(len(o.GATES),11)
    def test_11_distinct_fail_stages(self): self.assertEqual(len(set(o.STAGES)),11)
    def test_only_all_true_is_conditional(self):
        a=[False]*11
        for m in range(2048):
            case=[bool(m&(1<<i)) for i in range(11)]
            self.assertEqual(o.decide(case)[0]=='CONDITIONAL_RELAY', m==2047)
    def test_every_single_gate_failure_is_rejected(self):
        for i,expected in enumerate(o.STAGES):
            gates=[True]*11;gates[i]=False
            self.assertEqual(o.decide(gates)[0],expected)
    def test_normal_no_claim_before_context(self):
        for i in range(4):
            g=[True]*11;g[i]=False
            self.assertFalse(o.decide(g)[1])
    def test_fail_claim_attempt_still_terminal_process(self):
        g=[True]*11;g[4]=False
        result=o.decide(g)
        self.assertEqual(result[0],'CLAIM_REJECTED')
        self.assertTrue(result[1]);self.assertFalse(result[2])
    def test_no_record_set_without_claim(self):
        g=[True]*11;g[4]=False
        self.assertFalse(o.decide(g)[2])
    def test_set_failed_prevents_connect(self):
        g=[True]*11;g[6]=False
        self.assertFalse(o.decide(g)[3])
    def test_ssh_failed_after_connect_never_positive(self):
        for i in (8,9):
            g=[True]*11;g[i]=False
            self.assertNotEqual(o.decide(g)[0],'CONDITIONAL_RELAY')
            self.assertTrue(o.decide(g)[3])
    def test_revoked_after_channel_is_not_positive(self):
        g=[True]*11;g[-1]=False
        self.assertEqual(o.decide(g)[0],'REVOKED')
    def test_matrix_has_exactly_2048_cases(self):self.assertEqual(len(list(o.matrix())),2048)
    def test_matrix_has_no_duplicate_masks(self):
        m=[int(x.split('|')[0],16) for x in o.matrix()]
        self.assertEqual(len(set(m)),2048)
    def test_ordinal_not_equal_binary_counter_order(self):
        m=list(o.matrix())
        self.assertEqual(m[1].split('|')[0],'0400')
    def test_accepted_count_is_one(self):self.assertEqual(o.summary()['conditional_relay'],1)
    def test_stage_counts_reject_all_other_cases(self):
        d=o.summary()['stage_counts']
        self.assertEqual(sum(d.values()),2048)
        self.assertEqual(sum(v for k,v in d.items() if k!='CONDITIONAL_RELAY'),2047)
    def test_matrix_digest_pinned(self):self.assertEqual(o.summary()['sha256'],EXPECTED)
    def test_node_independence_and_exact_agreement(self):
        s=(ROOT/'r139_independent.mjs').read_text()
        self.assertNotIn('r139_receipt_oracle',s)
        d=json.loads(subprocess.check_output(['node',str(ROOT/'r139_independent.mjs')],text=True))
        self.assertEqual(d,o.summary())
    def test_bad_type_rejected(self):
        for wrong in ([True]*10, [1]+[True]*10, ['true']+[True]*10):
            with self.assertRaises(ValueError):o.decide(wrong)
    def test_no_kernel_proof_in_oracle(self):
        s=o.summary();self.assertFalse(s['kernel_origin_proof']);self.assertFalse(s['no_direct_proof'])
    def test_pinned_sha_in_source_gate(self):
        s=(ROOT/'FlowBridge-R139-SourceGate.ps1').read_text()
        for blob in ('16ec8853d322b40f0e00e14d49ae3410741b9395',
                     '0af6d4539673d2894cbaa91af0ea8f3524862a26',
                     '9a07e026134d46ef646d39862bd982cc48bbc5f6',
                     'acf60334320d970f58af3349ee75fbaa59826602'):
            self.assertIn(blob,s)
    def test_pinned_queries_and_claimer_checks(self):
        s=(ROOT/'FlowBridge-R139-SourceGate.ps1').read_text()
        for x in ('query(&accepted,QUERY_RECORDS,CAP)?','query(&accepted,QUERY_CONTEXT,h::LEN)?',
                  'device.command(h::CLAIM','WSAIoctl(s.0,SET_RECORDS','connect(s.0',
                  'FWPM_SESSION_FLAG_DYNAMIC','FWPS_RIGHT_ACTION_WRITE'):
            self.assertIn(x,s)
    def test_no_system_changes_or_sockets_in_source_gate(self):
        s=(ROOT/'FlowBridge-R139-SourceGate.ps1').read_text()
        for x in ('Set-ExecutionPolicy','New-NetFirewallRule','Start-Service','Stop-Service',
                  'rustup install','git checkout','Start-Process','Add-Type','DllImport'):
            self.assertNotIn(x,s)
    def test_source_gate_fails_on_changed_blocker_signature(self):
        s=(ROOT/'FlowBridge-R139-SourceGate.ps1').read_text()
        self.assertIn('if(-not $rights -or -not $dynamic)',s)
    def test_source_gate_no_go_is_nonzero(self):
        s=(ROOT/'FlowBridge-R139-SourceGate.ps1').read_text()
        self.assertIn("$exitCode=3",s)
        self.assertIn("$report.status='R139_SOURCE_RECEIPT_VALIDATED_RELEASE_NO_GO'",s)
    def test_source_gate_refuses_wrong_sha(self):
        s=(ROOT/'FlowBridge-R139-SourceGate.ps1').read_text()
        self.assertIn('if($git -cne $entry.Value)',s)
        self.assertIn('Git-Blob $bytes',s)
    def test_source_gate_sdk_not_install(self):
        s=(ROOT/'FlowBridge-R139-SourceGate.ps1').read_text()
        self.assertIn("'mstcpip.h'",s);self.assertIn('Get-ChildItem',s)
        self.assertIn('SDK_SYMBOLS_MISMATCH',s)

if __name__=='__main__': unittest.main(verbosity=2)
