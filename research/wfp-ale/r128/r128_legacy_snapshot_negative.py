#!/usr/bin/env python3
"""R128 offline truth table for legacy R113 vs hardened R124 BFE decisions."""
import hashlib
import unittest

def verdict(case, hardened):
    values = case['counts']
    if hardened:
        if any(type(v) is not int or not 0 <= v <= 131072 for v in values): return 2
        v = case['visible_filters']
        if type(v) is not int or not 4 <= v <= 131072 or sum(values)>v-4: return 2
    else:
        if any(type(v) not in (int,float,bool) or v<0 for v in values): return 2
    candidate=values[0]>0 or values[1]>0 or (
        hardened and case['rule_id']>=2 and values[2]>0)
    return 3 if candidate else 4

def cases():
    for rule_id in range(4):
        for field in range(4):
            for v in (0,1,.5,-1,True):
                for visible in (4,5):
                    values=[0,0,0,0]; values[field]=v
                    yield {'rule_id':rule_id,'field_id':field,'counts':values,
                           'visible_filters':visible}

def matrix():
    rows=[]
    for i,c in enumerate(cases()):
        v=c['counts'][c['field_id']]
        rows.append(f"{i},{c['rule_id']},{c['field_id']},{str(v).lower()},{c['visible_filters']},{verdict(c,False)},{verdict(c,True)}")
    payload='\n'.join(rows)+'\n'
    return len(rows),hashlib.sha256(payload.encode()).hexdigest(),payload

class R128Tests(unittest.TestCase):
    def test_old_misses_lower_redirect(self):
        for rule in (2,3):
            c={'rule_id':rule,'field_id':2,'counts':[0,0,1,0],'visible_filters':5}
            self.assertEqual(4,verdict(c,False))
            self.assertEqual(3,verdict(c,True))
    def test_old_accepts_impossible_cardinality(self):
        c={'rule_id':0,'field_id':0,'counts':[1,0,0,0],'visible_filters':4}
        self.assertEqual(3,verdict(c,False))
        self.assertEqual(2,verdict(c,True))
    def test_old_accepts_fraction_bool(self):
        for value in (.5,True):
            c={'rule_id':0,'field_id':0,'counts':[value,0,0,0],'visible_filters':5}
            self.assertEqual(3,verdict(c,False))
            self.assertEqual(2,verdict(c,True))
    def test_zero_unknown(self):
        c={'rule_id':0,'field_id':0,'counts':[0,0,0,0],'visible_filters':4}
        self.assertEqual(4,verdict(c,False))
        self.assertEqual(4,verdict(c,True))
    def test_negative_denied(self):
        c={'rule_id':1,'field_id':0,'counts':[-1,0,0,0],'visible_filters':5}
        self.assertEqual(2,verdict(c,False))
        self.assertEqual(2,verdict(c,True))
    def test_matrix(self):
        n,h,_=matrix()
        self.assertEqual(160,n)
        self.assertEqual('20cd16d5de1d43823bc3c98445eb29b7e3d0b36db61954056edecde037c87c33',h)

if __name__=='__main__':
    import sys
    if '--matrix' in sys.argv:
        n,h,p=matrix()
        from collections import Counter
        ct=Counter(tuple(map(int,row.split(',')[-2:])) for row in p.splitlines())
        print('cases=',n,'sha256=',h,'legacy_vs_hardened=',sorted(ct.items()))
    else:
        unittest.main()
