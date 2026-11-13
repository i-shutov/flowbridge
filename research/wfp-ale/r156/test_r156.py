#!/usr/bin/env python3
"""Offline test suite: executable correction of R155 callback-only inference."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('r156', ROOT/'r156_callback_composition.py')
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)

class Tests(unittest.TestCase):
    def test_source_pins_have_kernel_and_wrapper(self):
        self.assertEqual(len(model.PINS),4)
        self.assertIn('kernel/src/lib.rs', model.PINS)
        self.assertIn('kernel/src/action_rights.rs', model.PINS)
    def test_no_null_assumptions(self):
        for case in [(4,'SELF','PERMIT',True,'SELF_RETURN'),
                     (6,'SELF','PERMIT',2,'SELF_RETURN'),
                     (4,'INVALID','PERMIT',1,'SELF_RETURN'),
                     (4,'SELF','PERMIT',1,'UNKNOWN')]:
            with self.assertRaises(ValueError):model.callback_return(*case)
    def test_self_outgoing_is_continuation_with_write(self):
        for f in model.FAMILIES:
            for state in model.REDIRECT_STATES:
                for prior in model.ACTIONS:
                    self.assertEqual(model.callback_return(f,state,prior,1,'SELF_RETURN'),('CONTINUE',1,'OUTER_CONTINUE'))
    def test_r155_overstates_sixteen_paths_but_twelve_outputs_differ(self):
        changed=sum(int(model.callback_return(f,s,p,1,'SELF_RETURN')[0]!=p)
            for f in model.FAMILIES for s in model.REDIRECT_STATES for p in model.ACTIONS)
        self.assertEqual(changed,12)
    def test_no_write_early_returns_do_not_set_permit(self):
        for p in model.ACTIONS:
            self.assertEqual(model.callback_return(6,'PREVIOUS_SELF',p,0,'SELF_RETURN'),(p,0,'PRESERVED_NO_WRITE'))
    def test_no_write_veto_prior_permit_only(self):
        for phase in model.PATHS[2:]:
            self.assertEqual(model.callback_return(4,'SELF','PERMIT',0,phase),('BLOCK',0,'VETO_PERMIT_NO_WRITE'))
            for action in ('BLOCK','CONTINUE','NONE'):
                self.assertEqual(model.callback_return(4,'SELF',action,0,phase),(action,0,'PRESERVED_NO_WRITE'))
    def test_write_error_sets_block_and_clears_rights(self):
        for phase in model.PATHS[2:]:
            for action in model.ACTIONS:
                self.assertEqual(model.callback_return(4,'SELF',action,1,phase),('BLOCK',0,'BLOCK_WITH_WRITE'))
    def test_appid_mismatch_continues_not_block_with_write(self):
        self.assertEqual(model.callback_return(6,'PREVIOUS_SELF','BLOCK',1,'APPID_MISMATCH'),('CONTINUE',1,'OUTER_CONTINUE'))
    def test_matrix_count_digest(self):
        self.assertEqual(model.matrix()['cases'],224)
        self.assertEqual(model.matrix()['changed_r155_action_rows'],12)
        self.assertEqual(sum(model.matrix()['counts'].values()),224)
        self.assertEqual(model.matrix()['sha256'],'cb05f79b8587c56b01e0e285b4264294fdf29e9635f726297854e2898499d933')
    def test_node_independent_agrees(self):
        got=json.loads(subprocess.check_output(['node',str(ROOT/'r156_independent.mjs')],text=True))
        self.assertEqual(got,model.matrix())
    def test_optimized_modes_agree(self):
        for mode in ([],['-O'],['-OO']):
            got=json.loads(subprocess.check_output([sys.executable,*mode,'-B',str(ROOT/'r156_callback_composition.py'),'--model-only'],text=True))
            self.assertEqual(got,model.matrix())
    def test_missing_real_source_is_no_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):model.source_gate(Path(tmp))
    def test_pin_drift_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in model.PINS:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(b'forged')
            with self.assertRaisesRegex(ValueError,'SOURCE_DRIFT'):
                model.source_gate(root)
    def test_no_implicit_model_qa(self):
        r=subprocess.run([sys.executable,'-B',str(ROOT/'r156_callback_composition.py')],capture_output=True)
        self.assertNotEqual(r.returncode,0)
    def test_no_driver_claim(self):
        for field in ('model_only','release_accepted','kernel_executed','no_direct_proved'):
            self.assertIs(model.matrix()[field],field=='model_only')
    def test_exhaustive_cases_are_unique(self):
        cases=[(f,s,a,w,p) for f in model.FAMILIES for s in model.REDIRECT_STATES
               for a in model.ACTIONS for w in (0,1) for p in model.PATHS]
        self.assertEqual(len(cases),224)
        self.assertEqual(len(set(cases)),224)

if __name__=='__main__':unittest.main(verbosity=2)
