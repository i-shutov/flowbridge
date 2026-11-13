#!/usr/bin/env python3
"""Offline independent acceptance smoke tests for R153 negative campaign."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT/'r153_cross_layer_barrier.py'
SOURCE = ROOT.parent/'r152'/'r152_aba_negative.py'
spec = importlib.util.spec_from_file_location('r153', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ClosureTests(unittest.TestCase):
    def test_schedules_are_consistent(self):
        schedules = list(m.schedules())
        self.assertEqual(len(schedules), 28)
        for s in schedules:
            self.assertEqual(len(set(s)),len(m.EVENTS))
            for k, required in m.BEFORE.items():
                for prev in required:
                    self.assertLess(s.index(prev), s.index(k))

    def test_conservative_quarantine(self):
        for s in m.schedules():
            for same in (True,False):
                self.assertEqual(m.classify(s,same,False),'REUSE_QUARANTINED')

    def test_accepted_twin_is_hypothetical(self):
        examples=[s for s in m.schedules() if s.index('AUTH_OLD_RESUME')>s.index('ISSUE_NEW')]
        self.assertEqual(len(examples),13)
        for s in examples:
            self.assertEqual(m.classify(s,True,True),'STALE_AUTH_ALIAS')
            self.assertEqual(m.classify(s,False,True),'OBSERVABLE_DIFFERENCE')

    def test_pinned_r152_source(self):
        m.pin(SOURCE,m.R152_BLOB)

    def test_mutated_r152_fails_normal_and_optimized(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'mutated.py'
            source.write_bytes(SOURCE.read_bytes()+b'\n# mutation\n')
            for flags in ((),('-O',),('-OO',)):
                proc=subprocess.run([sys.executable,*flags,'-B',str(SCRIPT),'--r152-source',str(source)],
                                    capture_output=True,timeout=30)
                self.assertNotEqual(proc.returncode,0)
                self.assertIn(b'SOURCE_PIN_MISMATCH',proc.stderr)
                self.assertNotIn(b'"cases"',proc.stdout)

    def test_modes_and_node_independent(self):
        values=[]
        for flags in ((),('-O',),('-OO',)):
            p=subprocess.run([sys.executable,*flags,'-B',str(SCRIPT),'--r152-source',str(SOURCE)],
                             capture_output=True,timeout=30,check=True)
            values.append(json.loads(p.stdout))
        p=subprocess.run(['node',str(ROOT/'r153_independent.mjs')],capture_output=True,timeout=30,check=True)
        values.append(json.loads(p.stdout))
        self.assertTrue(all(x==values[0] for x in values))
        self.assertEqual(values[0]['cases'],224)
        self.assertFalse(values[0]['native_wfp_executed'])
        self.assertFalse(values[0]['cross_layer_barrier_proved'])
        self.assertFalse(values[0]['release_accepted'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
