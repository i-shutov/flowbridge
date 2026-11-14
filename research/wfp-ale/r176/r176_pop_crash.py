#!/usr/bin/env python3
"""R176: deterministic user-mode projection, NOT Windows or kernel proof."""
import json
import unittest
from collections import deque

class Kernel:
    def __init__(self):
        self.queue = deque()
        self.counter = 0
        self.lost = False
    def observe(self):
        if self.lost or len(self.queue) == 32:
            self.lost = True
            return False
        self.counter += 1
        self.queue.append(self.counter)
        return True
    def pop(self):
        if self.lost:
            return ('NOT_READY', None)
        if not self.queue:
            return ('EMPTY', None)
        return ('SUCCESS', self.queue.popleft())

class Reader:
    def __init__(self):
        self.volatile = []
        self.durable = []
    def read(self, kernel):
        status, receipt = kernel.pop()
        if status == 'SUCCESS':
            self.volatile.append(receipt)
        return status
    def persist_one(self):
        self.durable.append(self.volatile.pop(0))
    def crash_and_restart(self):
        self.volatile.clear()

def case(family, n, precrash_reads, persisted):
    k, b = Kernel(), Reader()
    for _ in range(n):
        ok = k.observe()
        if not ok: raise RuntimeError("Unexpected overflow")
    for _ in range(precrash_reads):
        status = b.read(k)
        if status != 'SUCCESS': raise RuntimeError(status)
    for _ in range(persisted):
        b.persist_one()
    b.crash_and_restart()
    for _ in range(n-precrash_reads):
        status = b.read(k)
        if status != 'SUCCESS': raise RuntimeError(status)
        b.persist_one()
    status, _ = k.pop()
    durable = b.durable
    missing = [i for i in range(1, n+1) if i not in durable]
    return dict(family=family,n=n,reads=precrash_reads,persisted=persisted,
                durable=durable,missing=missing,empty=status=='EMPTY',lost=k.lost,
                tail_silent=bool(missing) and missing[-1]==n)

def matrix():
    for family in (4,6):
        for n in range(1,6):
            for reads in range(n+1):
                for persisted in range(reads+1):
                    yield case(family,n,reads,persisted)

class Tests(unittest.TestCase):
    def test_live_owner_pop_deletes_before_processing(self):
        self.assertEqual(case(4,1,1,0)['missing'],[1])
    def test_empty_does_not_report_loss(self):
        x=case(6,1,1,0)
        self.assertTrue(x['empty'])
        self.assertFalse(x['lost'])
    def test_crash_before_read_is_recoverable(self):
        self.assertEqual(case(4,2,0,0)['missing'],[])
    def test_persist_before_crash_is_recoverable(self):
        self.assertEqual(case(4,2,2,2)['missing'],[])
    def test_middle_gap_visible_only_later(self):
        self.assertEqual(case(6,2,1,0)['missing'],[1])
        self.assertEqual(case(6,2,1,0)['durable'],[2])
    def test_tail_loss_no_following_receipt(self):
        x=case(4,3,3,1)
        self.assertEqual(x['durable'],[1]);self.assertEqual(x['missing'],[2,3])
        self.assertTrue(x['tail_silent'])
    def test_32_live_receipts_can_disappear_without_sticky_error(self):
        self.assertEqual(case(4,32,32,0)['missing'],list(range(1,33)))
        self.assertFalse(case(4,32,32,0)['lost'])
    def test_33rd_unread_record_is_sticky_failure(self):
        k=Kernel()
        for _ in range(32):self.assertTrue(k.observe())
        self.assertFalse(k.observe());self.assertTrue(k.lost)
        self.assertEqual(k.pop()[0],'NOT_READY')
    def test_exhaustive_model_sanity(self):
        rows=list(matrix());self.assertEqual(len(rows),110)
        for x in rows:
            self.assertEqual(sorted(x['durable']+x['missing']),list(range(1,x['n']+1)))
            self.assertFalse(x['lost'])
            self.assertTrue(x['empty'])

if __name__=='__main__':
    import sys
    if '--matrix' in sys.argv:
        for row in matrix():print(json.dumps(row,sort_keys=True,separators=(',',':')))
    else:
        unittest.main(argv=[sys.argv[0]])
