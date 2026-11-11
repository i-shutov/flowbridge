#!/usr/bin/env python3
"""R110 independent read-only BFE snapshot regression (synthetic only)."""
import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = (ROOT / 'r103_readonly_arbitration_inventory.rs').read_text()
RULES = ('auth_v4','auth_v6','redirect_v4','redirect_v6')
WEIGHTS = (0, 10, 20, 30)  # zero = baseline not visible in enum snapshot
FOREIGN = (0, 5, 10, 15, 20, 25, 35)

def decision(old_own, new_own, foreign, foreign_visible):
    old_assumes_candidate = old_own > 0 and foreign_visible and foreign >= old_own
    if new_own == 0:
        new = 'UNKNOWN'  # baseline missing, fail diagnostic closed
    elif foreign_visible and foreign >= new_own:
        new = 'VISIBLE_ARBITRATION_CANDIDATE'
    else:
        new = 'UNKNOWN_NO_VISIBLE_CANDIDATE'
    return old_assumes_candidate, new

def matrix():
    rows = []
    for i in range(4):
        for old in WEIGHTS:
            for now in WEIGHTS:
                for foreign in FOREIGN:
                    for vis in (0,1):
                        old_candidate, new_status = decision(old,now,foreign,vis)
                        rows.append([i,old,now,foreign,vis,int(old_candidate),new_status])
    return rows

def summary():
    rows = matrix()
    txt = '\n'.join('|'.join(map(str,row)) for row in rows) + '\n'
    missing = sum(row[6] == 'UNKNOWN' for row in rows)
    old_false = sum(row[5] == 1 and row[6] != 'VISIBLE_ARBITRATION_CANDIDATE' for row in rows)
    old_missed = sum(row[5] == 0 and row[6] == 'VISIBLE_ARBITRATION_CANDIDATE' for row in rows)
    return {'cases':len(rows),'missing_baseline_unknown':missing,
            'old_mixed_snapshot_overreports':old_false,'old_mixed_snapshot_underreports':old_missed,
            'decision_sha256':hashlib.sha256(txt.encode()).hexdigest(),
            'native_windows_executed':False,'kernel_proof':False}

class TestSource(unittest.TestCase):
    def test_no_explicit_bfe_transaction_in_long_enum(self):
        for disallowed in ('FwpmTransactionBegin0','FwpmTransactionCommit0','FwpmTransactionAbort0','FWPM_TXN_READ_ONLY','Txn::new'):
            self.assertNotIn(disallowed,SRC)
    def test_one_snapshot_for_own_and_foreign(self):
        self.assertIn('FwpmFilterCreateEnumHandle0(engine.0,ptr::null(),&mut eh)',SRC)
        self.assertIn('let mut owned_weights:[Option<u64>;4]=[None;4];',SRC)
        self.assertIn('let mut foreign_weights:[Vec<u64>;4]=std::array::from_fn',SRC)
        self.assertIn('owned_weights[i]=Some(effective(f)',SRC)
        self.assertIn('foreign_weights[i].push(effective(f)',SRC)
        self.assertNotIn('FwpmFilterGetByKey0',SRC)
    def test_baseline_is_obligatory(self):
        self.assertIn('owned_weights[i].ok_or(("baseline_not_visible",1))?',SRC)
    def test_same_layer_and_sublayer(self):
        self.assertIn('f.layer==LAYERS[i] && f.sublayer==SUB',SRC)
        self.assertIn('f.layer!=LAYERS[i]||f.sublayer!=SUB||f.weight.kind!=FWP_EMPTY',SRC)
    def test_budget_enumerator_cleanup(self):
        for term in ('if returned>PAGE','enum_budget_exceeded','enumerator.destroy()?','FwpmFilterDestroyEnumHandle0'):
            self.assertIn(term,SRC)
    def test_only_management_read_methods(self):
        for bad in ('FwpmFilterAdd0','FwpmFilterDelete','FwpmCalloutAdd0','FwpmCalloutRegister','FwpmEngineSetOption','WSAIoctl','socket('):
            self.assertNotIn(bad,SRC)
    def test_no_safe_status(self):
        self.assertNotIn('"SAFE"',SRC)
        self.assertIn('"kernel_proof\\":false',SRC)
        self.assertIn('"no_direct_proof\\":false',SRC)
    def test_old_mixed_false_candidate(self):
        old,new=decision(10,20,15,1)
        self.assertTrue(old)
        self.assertEqual(new,'UNKNOWN_NO_VISIBLE_CANDIDATE')
    def test_old_mixed_false_negative(self):
        old,new=decision(20,10,15,1)
        self.assertFalse(old)
        self.assertEqual(new,'VISIBLE_ARBITRATION_CANDIDATE')
    def test_baseline_hidden_is_unknown_even_with_foreign(self):
        for foreign in FOREIGN:
            for v in (0,1):
                self.assertEqual(decision(20,0,foreign,v)[1],'UNKNOWN')
    def test_four_rule_domains(self):
        self.assertEqual(len(RULES),4)
        self.assertIn('const LAYERS:[Guid;4]',SRC)
    def test_enumerator_results_are_not_proof(self):
        for row in matrix():
            self.assertIn(row[6],('UNKNOWN','VISIBLE_ARBITRATION_CANDIDATE','UNKNOWN_NO_VISIBLE_CANDIDATE'))
    def test_matrix_size_and_disagreements(self):
        s=summary()
        self.assertEqual(s['cases'],896)
        self.assertGreater(s['old_mixed_snapshot_overreports'],0)
        self.assertGreater(s['old_mixed_snapshot_underreports'],0)

if __name__=='__main__':
    unittest.main(verbosity=2)
    print('R110_SUMMARY='+json.dumps(summary(),sort_keys=True))
