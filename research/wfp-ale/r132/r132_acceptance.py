#!/usr/bin/env python3
"""Independent local acceptance: pins, scope, oracle and mutation controls."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import re
import subprocess
import unittest
ROOT=Path(__file__).resolve().parent
REPO=ROOT.parents[2]
spec=importlib.util.spec_from_file_location('oracle',ROOT/'r132_oracle.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
EXPECTED='c2af3f996ec4c52620c973f0fb34dc4ead470e94f6805edeb9a8d49fcf278e37'

class Acceptance(unittest.TestCase):
    def test_source_pin_sha1_and_sha256(self):
        for p in json.loads((ROOT/'r132_source_pins.json').read_text()):
            raw=(REPO/p['path']).read_bytes()
            self.assertEqual(hashlib.sha1(f'blob {len(raw)}\0'.encode()+raw).hexdigest(),p['git_blob'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),p['sha256'])
    def test_powershell_pin_manifest_is_exact(self):
        ps=(ROOT/'FlowBridge-R132-EventOrders.ps1').read_text()
        embedded=re.search(r"\$files = @'\n(.*?)\n'@ \| ConvertFrom-Json",ps,re.S).group(1)
        self.assertEqual(json.loads(embedded),json.loads((ROOT/'r132_source_pins.json').read_text()))
    def test_exact_test_counts(self):
        for path,count in [('kernel-r19/kernel/src/ledger.rs',11),('kernel-r19/kernel/src/handoff.rs',19),('kernel-r19/kernel/src/auth_appid.rs',7),('kernel-r19/policy_plan.rs',9),('r132/r132_event_orders.rs',18)]:
            self.assertEqual((ROOT.parent/path).read_text().count('#[test]'),count)
    def test_rust_surface_is_pure(self):
        s=(ROOT/'r132_event_orders.rs').read_text()
        self.assertIn('#![forbid(unsafe_code)]',s)
        self.assertNotRegex(s,r'\bunsafe\s+(?:fn|extern|\{)')
        self.assertNotRegex(s,r'(?m)^\s*(?:use|extern)\s+(?:windows|tokio|libc)')
        self.assertNotIn('std::net',s)
        self.assertNotRegex(s,r'\bFwpm\w+\s*\(')
    def test_claim_order_matches_analyzed_adapter(self):
        s=(ROOT/'r132_event_orders.rs').read_text().split('fn claim(')[1].split('fn primary')[0]
        self.assertLess(s.index('self.book.take'),s.index('self.ledger.lookup'))
    def test_permutations_cover_every_position(self):
        self.assertEqual(len(o.ORDERS),720);self.assertEqual(len(set(o.ORDERS)),720)
        for event in range(6):
            for pos in range(6): self.assertEqual(sum(p[pos]==event for p in o.ORDERS),120)
    def test_full_oracle_hash(self):
        result=o.summarize(o.campaign())
        self.assertEqual(result['sha256'],EXPECTED);self.assertEqual(result['traces'],36000)
        self.assertEqual(result['accepted_claims'],4944)
    def test_node_independence_and_agreement(self):
        s=(ROOT/'r132_independent.mjs').read_text();self.assertNotIn('r132_oracle',s)
        result=json.loads(subprocess.check_output(['node',str(ROOT/'r132_independent.mjs')],text=True))
        self.assertEqual(result,o.summarize(o.campaign()))
    def test_no_acceptance_after_applied_hazard_or_expiry(self):
        for h in range(5):
            for v in range(5):
                for order in o.ORDERS:
                    bits=o.trace(h,v,order)[0]
                    for i,e in enumerate(order):
                        if e in (2,3) and bits[i]=='1':
                            self.assertNotIn(5,order[:i])
                            if h: self.assertNotIn(4,order[:i])
    def test_two_claims_and_two_auths_never_both_succeed(self):
        for h in range(5):
            for v in range(5):
                for p in o.ORDERS:
                    b=o.trace(h,v,p)[0]
                    self.assertLessEqual(sum(b[i]=='1' for i,e in enumerate(p) if e in (2,3)),1)
                    self.assertLessEqual(sum(b[i]=='1' for i,e in enumerate(p) if e in (0,1)),1)
    def test_failed_payload_vs_foreign_session(self):
        p=(0,2,3,1,4,5)
        self.assertEqual(o.trace(0,1,p)[0][:3],'100')
        self.assertEqual(o.trace(0,2,p)[0][:3],'101')
    def test_early_claim_cannot_be_repaired(self):
        p=(2,0,3,1,4,5)
        self.assertEqual(o.trace(0,0,p)[0][:4],'0000')
    def test_mutant_omits_liveness_is_detected(self):
        p=(0,4,2,3,1,5)
        self.assertNotEqual(o.trace(1,0,p),o.trace(1,0,p,'omit_claim_liveness'))
    def test_mutant_failed_claim_not_terminal_is_detected(self):
        p=(2,0,3,1,4,5)
        self.assertNotEqual(o.trace(0,0,p),o.trace(0,0,p,'nonterminal_failed_claim'))
    def test_script_never_asks_for_bfe_or_installs(self):
        s=(ROOT/'FlowBridge-R132-EventOrders.ps1').read_text()
        for term in ('-RunReadOnlyBfe','Start-Service','New-NetFirewallRule','Set-ExecutionPolicy','rustup install','git checkout','git reset'):
            self.assertNotIn(term,s)
        self.assertIn("'--forbid','unsafe_code'",s)
        self.assertIn('WaitForExit(180000)',s)
    def test_campaign_and_test_acceptance_cannot_skip(self):
        s=(ROOT/'FlowBridge-R132-EventOrders.ps1').read_text()
        for term in (EXPECTED,'$expectedTests = 64','$expectedTraces = 36000',"@('schedule_tests',18)","@('--campaign')",'$lines.Count -ne $expectedTraces','$report.campaign_sha256 -cne $expectedCampaignHash','64 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'):
            self.assertIn(term,s)
    def test_crlf_and_mutation_are_not_silently_normalized(self):
        p=json.loads((ROOT/'r132_source_pins.json').read_text())[-1];raw=(REPO/p['path']).read_bytes()
        for altered in (raw.replace(b'\n',b'\r\n'),raw[:-1],b'\xef\xbb\xbf'+raw,raw+b' '):
            self.assertNotEqual(hashlib.sha256(altered).hexdigest(),p['sha256'])
    def test_thread_tests_have_bounded_order_control(self):
        s=(ROOT/'r132_event_orders.rs').read_text()
        self.assertIn('Barrier::new(3)',s);self.assertIn('Mutex::new(m)',s)
        self.assertIn('recv_timeout(Duration::from_secs(10))',s)
        self.assertIn('.stack_size(8*1024*1024)',s)

if __name__=='__main__': unittest.main(verbosity=2)
