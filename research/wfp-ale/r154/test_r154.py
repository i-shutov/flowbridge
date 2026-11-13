#!/usr/bin/env python3
"""Unit tests for a conditionally projected R19 provenance model."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('r154',HERE/'r154_compartment_negative.py')
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Cases(unittest.TestCase):
    def test_provenance_projection_gap_both_families(self):
        for family in (4,6):
            self.assertEqual(m.outcome(family,True,True,True,'different',True,True),'COMPARTMENT_UNBOUND_CONDITIONAL')
            self.assertEqual(m.outcome(family,True,True,True,'missing',True,True),'COMPARTMENT_UNBOUND_CONDITIONAL')
    def test_normal_matching_is_not_native(self):
        self.assertEqual(m.run()['categories']['MATCHED_MODEL_ONLY'],2)
        self.assertFalse(m.run()['native_wfp_executed'])
    def test_rights_or_epoch_or_endpoint_disqualify(self):
        for f in (4,6):
            for arg in (
                (True,False,True,'different',True,True),
                (True,True,False,'different',True,True),
                (False,True,True,'different',True,True),
                (True,True,True,'different',True,False),
                (True,True,True,'different',False,True)):
                self.assertEqual(m.outcome(f,*arg),'OTHER_REQUIRED_FIELD_REJECTED')
    def test_model_only_requires_explicit_mark(self):
        c=subprocess.run([sys.executable,'-B',str(HERE/'r154_compartment_negative.py')],capture_output=True)
        self.assertNotEqual(c.returncode,0)
    def test_source_gate_missing_refuses(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as tmp:
            c=subprocess.run([sys.executable,'-O','-B',str(HERE/'r154_compartment_negative.py'),
                              '--source-root',tmp],capture_output=True)
            self.assertNotEqual(c.returncode,0)
    def test_blobs_not_authority(self):
        result=m.run()
        for flag in ('native_wfp_executed','endpoint_reuse_observed','release_accepted','compartment_evidence_proved'):
            self.assertIs(result[flag],False)

if __name__=='__main__':unittest.main(verbosity=2)
