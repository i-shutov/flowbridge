#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import subprocess
import sys
import json
import unittest
from unittest.mock import patch
import tempfile

HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('r155',HERE/'r155_terminating_action_negative.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Tests(unittest.TestCase):
    def test_matrix_size(self):self.assertEqual(r.matrix()['states'],32)
    def test_self_permit_is_inherited_only(self):
        for family in (4,6):
            for right in (0,1):
                self.assertEqual(r.verdict('SELF','PERMIT',right,family),('SELF_RETURN_UNSET','PERMIT'))
    def test_self_continue_is_inherited_not_explicit(self):
        self.assertEqual(r.verdict('SELF','CONTINUE',1,4),('SELF_RETURN_UNSET','CONTINUE'))
    def test_previous_self_is_not_explicit_auth_verdict(self):
        self.assertEqual(r.verdict('PREVIOUS_SELF','BLOCK',0,6),('PREVIOUS_SELF_UNSET','BLOCK'))
    def test_invalid_input(self):
        for args in [('SELF','ABORT',1,4),('OTHER','PERMIT',1,4),('SELF','PERMIT',2,4),('SELF','PERMIT',1,7)]:
            with self.assertRaises(ValueError):r.verdict(*args)
    def test_independent_node(self):
        got=subprocess.check_output(['node',str(HERE/'r155_independent.mjs')],text=True)
        self.assertEqual(json.loads(got),r.matrix())
    def test_model_only_required(self):
        run=subprocess.run([sys.executable,'-B',str(HERE/'r155_terminating_action_negative.py')],capture_output=True)
        self.assertNotEqual(run.returncode,0)
    def test_missing_source_does_not_count_as_pin(self):
        with self.assertRaises(FileNotFoundError):r.source_gate(Path('/this/source/does/not/exist'))
    def test_pin_drift_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'kernel/src').mkdir(parents=True)
            (root/'kernel/src/redirect.rs').write_bytes(b'unsafe synthetic code')
            (root/'policy_windows.rs').write_bytes(b'fake policy')
            with self.assertRaisesRegex(ValueError, 'R19_BLOB_DRIFT'):
                r.source_gate(root)

    def test_matrix_categories_do_not_claim_native_proof(self):
        result=r.matrix()
        for key in ('source_is_runtime_proof','native_wfp_executed','release_accepted'):
            self.assertIs(result[key], False)
        self.assertEqual(result['categories']['INHERITED_CONTINUE'],8)

    def test_optimized_matches(self):
        expected=r.matrix()
        for opt in ('-O','-OO'):
            got=subprocess.check_output([sys.executable,opt,'-B',str(HERE/'r155_terminating_action_negative.py'),'--model-only'],text=True)
            self.assertEqual(json.loads(got),expected)
if __name__=='__main__':unittest.main(verbosity=2)
