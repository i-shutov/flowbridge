#!/usr/bin/env python3
"""R95 deterministic negative oracle: assumes R94's eight objects and four shape checks pass.
No Windows API or socket is used. 0/1 masks are per AUTHv4, AUTHv6, REDIRECTv4, REDIRECTv6.
"""
from __future__ import annotations
import hashlib
import unittest

EXPECTED_TYPES = (0x5003, 0x5003, 0x4005, 0x4005)
MASK = 15

def old(reg: int, _atype: int, _key: int, _count: int) -> bool:
    return reg == MASK

def new(reg: int, atype: int, key: int, count: int) -> bool:
    return all(((m >> n) & 1) for n in range(4) for m in (reg, atype, key, count))

def cases():
    for reg in range(16):
        for atype in range(16):
            for key in range(16):
                for count in range(16):
                    yield f'{reg:x},{atype:x},{key:x},{count:x},{int(old(reg,atype,key,count))},{int(new(reg,atype,key,count))}'

class GateTests(unittest.TestCase):
    def test_rule_types(self):
        self.assertEqual(EXPECTED_TYPES, (0x00005003,0x00005003,0x00004005,0x00004005))
    def test_mutating_any_single_rule_fails(self):
        self.assertTrue(new(15,15,15,15))
        for axis in range(4):
            a=[15,15,15,15]; a[axis] &= ~1
            self.assertTrue(old(*a) if axis != 0 else not old(*a))
            self.assertFalse(new(*a))
        for i in range(4):
            self.assertNotEqual(EXPECTED_TYPES[i],0x1002)  # FWP_ACTION_PERMIT
            self.assertFalse(new(15,15^(1<<i),15,15))
            self.assertFalse(new(15,15,15^(1<<i),15))
            self.assertFalse(new(15,15,15,15^(1<<i)))
    def test_exhaustive(self):
        old_pass=new_pass=old_false_positive=total=0
        for reg in range(16):
            for atype in range(16):
                for key in range(16):
                    for count in range(16):
                        before=old(reg,atype,key,count); after=new(reg,atype,key,count)
                        total += 1; old_pass += before; new_pass += after
                        old_false_positive += before and not after
        self.assertEqual((total,old_pass,new_pass,old_false_positive),(65536,4096,1,4095))

if __name__ == '__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(GateTests))
    sha=hashlib.sha256(('\n'.join(cases())+'\n').encode()).hexdigest()
    print('R95_MATRIX_SHA256',sha,'ROWS',65536,'OLD',4096,'NEW',1,'OLD_FALSE_POSITIVES',4095)
    raise SystemExit(0 if result.wasSuccessful() else 1)
