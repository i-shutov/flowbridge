#!/usr/bin/env python3
"""R94 registration snapshot oracle; deterministic only, no Windows calls."""
from __future__ import annotations
import hashlib
import re
import unittest
from pathlib import Path
SOURCE = Path(__file__).resolve().parent.parent / "r93" / "r93_readonly_policy_inventory.rs"
FLAG = 0x00040000

def old_shape(objects:int, shape:int)->bool:
    return objects == 255 and shape == 15

def strict_gate(objects:int, shape:int, registered:int)->bool:
    return old_shape(objects,shape) and registered == 15

def matrix():
    for objects in range(256):
        for shape in range(16):
            for reg in range(16):
                yield f"{objects:03x},{shape:x},{reg:x},{int(old_shape(objects,shape))},{int(strict_gate(objects,shape,reg))}"

class R94Tests(unittest.TestCase):
    def test_source_guard(self):
        src=SOURCE.read_text(encoding="utf-8")
        self.assertRegex(src,r"const FWPM_CALLOUT_FLAG_REGISTERED:\s*u32\s*=\s*0x00040000;")
        self.assertIn("(flags & FWPM_CALLOUT_FLAG_REGISTERED) != 0",src)
        self.assertIn("cs == 0 && !callout.0.is_null()",src)
        self.assertIn("shape_complete && registered_snapshot_complete",src)
        for key in ('snapshot_gate_complete','kernel_origin_proof','continuous_enforcement_proof'):
            self.assertIn(key,src)
    def test_readonly_api_allowlist(self):
        s=SOURCE.read_text(encoding="utf-8")
        block=s.split('unsafe extern "system" {',1)[1].split('\n    }',1)[0]
        names=set(re.findall(r"fn (Fwpm\w+0)\(",block))
        self.assertEqual(names,{"FwpmEngineOpen0","FwpmEngineClose0","FwpmFilterGetByKey0","FwpmCalloutGetByKey0","FwpmFreeMemory0"})
        for mutator in ("FwpmFilterAdd0","FwpmCalloutAdd0","FwpmFilterDelete","FwpmTransaction","socket("):
            self.assertNotIn(mutator,s)
    def test_unregistered_shape_positive_is_rejected(self):
        self.assertTrue(old_shape(255,15))
        self.assertTrue(strict_gate(255,15,15))
        for reg in range(15):
            self.assertFalse(strict_gate(255,15,reg))
    def test_flag_bitmask(self):
        self.assertEqual(FLAG,0x00040000)
        self.assertFalse(bool(FLAG & 0x00010000))
        self.assertTrue(bool((FLAG | 0x00010000) & FLAG))
    def test_complete_matrix(self):
        rows=list(matrix())
        self.assertEqual(len(rows),65536)
        self.assertEqual(len(set(rows)),65536)
        self.assertEqual(sum(row.endswith(',1,1') for row in rows),1)
        self.assertEqual(sum(row.endswith(',1,0') for row in rows),15)
if __name__=="__main__":
    r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(R94Tests))
    print("R94_MATRIX_SHA256",hashlib.sha256(('\n'.join(matrix())+'\n').encode()).hexdigest())
    print("ROWS",65536,"OLD",16,"NEW",1,"LEGACY_FALSE_POSITIVES",15)
    raise SystemExit(0 if r.wasSuccessful() else 1)
