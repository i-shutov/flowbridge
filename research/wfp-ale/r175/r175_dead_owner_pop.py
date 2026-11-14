#!/usr/bin/env python3
"""R175 offline projection of pinned R19 Ledger::pop and dispatch; NOT WFP proof."""
from dataclasses import dataclass
import json,sys,unittest

@dataclass(frozen=True)
class Receipt:
    number:int
    pid:int
    family:int

class Ledger:
    def __init__(self, mutant=False):
        self.owners={101:True,202:True}
        self.queue=[]
        self.receipt=0
        self.lost=False
        self.mutant=mutant
    def observe(self,pid,family):
        assert pid in self.owners and self.owners[pid] and family in (4,6)
        assert len(self.queue)<32
        self.receipt+=1
        self.queue.append(Receipt(self.receipt,pid,family))
    def died(self,pid):self.owners[pid]=False
    def pop_ioctl(self):
        if self.lost:return ('NOT_READY',0,None)
        if not self.queue:return ('EMPTY',0,None)
        w=self.queue.pop(0)  # R19 removes FIRST
        if not self.owners[w.pid]:
            # The controlled mutant models a fail-sticky alternative; this is
            # explicitly NOT what actual R19 source currently does.
            if self.mutant:self.lost=True
            return ('NOT_READY',0,None) # dispatch erases the receipt identity
        return ('SUCCESS',592,w.number) # repr(C) Witness: 80 header + 512 AppId bytes

def order(kind,dead,live):
    if kind=='dead-first':return [101]*dead+[202]*live
    if kind=='live-first':return [202]*live+[101]*dead
    result=[]
    for i in range(max(dead,live)):
        if i<dead:result.append(101)
        if i<live:result.append(202)
    return result

def matrix(mutant=False):
    rows=[]
    for family in [4,6]:
        for kind in ('dead-first','live-first','alternating'):
            for d in range(1,5):
                for l in range(4):
                    sequence=order(kind,d,l)
                    q=Ledger(mutant)
                    for pid in sequence:q.observe(pid,family)
                    q.died(101)
                    responses=[q.pop_ioctl() for _ in range(len(sequence)+1)]
                    rows.append(dict(case=f'{family}/{kind}/{d}/{l}',
                        family=family,initial_receipts=len(sequence),
                        status=[t[0] for t in responses],
                        visible_receipts=[t[2] for t in responses if t[0]=='SUCCESS'],
                        lost=q.lost,
                        # R19: NOT_READY has no receipt number or output bytes
                        opaque_errors=sum(t[0]=='NOT_READY' for t in responses),
                        tail=responses[-1][0]))
    return rows

class Tests(unittest.TestCase):
    def test_dead_owner_drops_before_validation(self):
        l=Ledger();l.observe(101,4);l.observe(202,4);l.died(101)
        self.assertEqual(l.pop_ioctl(),('NOT_READY',0,None))
        self.assertFalse(l.lost)
        self.assertEqual(l.pop_ioctl()[0:1],('SUCCESS',))
        self.assertEqual(l.pop_ioctl(),('EMPTY',0,None))
    def test_only_dead_owner_reports_error_then_empty(self):
        l=Ledger();l.observe(101,6);l.died(101)
        self.assertEqual(l.pop_ioctl(),('NOT_READY',0,None))
        self.assertEqual(l.pop_ioctl(),('EMPTY',0,None))
    def test_gap_after_dead_receipts(self):
        l=Ledger()
        for pid in [101,101,202]:l.observe(pid,4)
        l.died(101)
        self.assertEqual([l.pop_ioctl()[0] for _ in range(3)],['NOT_READY','NOT_READY','SUCCESS'])
        self.assertFalse(l.lost)
    def test_both_families_and_96_rows(self):
        rows=matrix();self.assertEqual(len(rows),96)
        self.assertTrue(all(r['opaque_errors']>=1 and not r['lost'] and r['tail']=='EMPTY' for r in rows))
        self.assertTrue(any(r['visible_receipts'] and r['visible_receipts'][0]>1 for r in rows))
    def test_mutation_detects_nonsticky_semantics(self):
        native=matrix();sticky=matrix(True)
        self.assertTrue(any(a!=b for a,b in zip(native,sticky)))
        self.assertFalse(any(r['lost'] for r in native))
        self.assertTrue(any(r['lost'] for r in sticky))

if __name__=='__main__':
    if '--matrix' in sys.argv:
        for r in matrix(): print(json.dumps(r,sort_keys=True,separators=(',',':')))
    else:unittest.main()
