#!/usr/bin/env python3
"""R177 deterministic clean-room user-mode model. NOT kernel/WFP evidence."""
import json
import sys
import unittest
from collections import deque
from dataclasses import dataclass

CAP = 32
TTL = 5

@dataclass(frozen=True)
class Reader:
    pid: int
    epoch: int
    executable: str

TRUSTED = Reader(707, 1700, r"\Device\HarddiskVolume3\FlowBridgeBroker.exe")
SIBLING = Reader(707, 1701, TRUSTED.executable)
OTHER = Reader(709, 1700, TRUSTED.executable)

@dataclass(frozen=True)
class Entry:
    session: int
    receipt: int
    tx: int
    endpoint: int
    family: int
    owner_epoch: int
    tombstone: bool = False

@dataclass(frozen=True)
class Token:
    session: int
    reader: Reader
    receipt: int
    tx: int
    delivery_generation: int

def must(ok, message):
    if not ok: raise RuntimeError(message)

class Kernel:
    def __init__(self, session, family):
        self.session, self.family = session, family
        self.queue = deque()
        self.next_receipt = 0
        self.next_generation = 0
        self.lease = None
        self.lost = False
        self.seen_endpoints = set()
        self.seen_tx = set()
    def observe(self, endpoint, tx, epoch=800):
        if self.lost: return False
        if endpoint in self.seen_endpoints or tx in self.seen_tx or len(self.queue) == CAP:
            self.lost = True
            return False
        self.next_receipt += 1
        self.seen_endpoints.add(endpoint)
        self.seen_tx.add(tx)
        self.queue.append(Entry(self.session, self.next_receipt, tx, endpoint, self.family, epoch))
        return True
    def peek(self, reader, now):
        if self.lost or reader != TRUSTED or not self.queue: return None
        if self.lease and now < self.lease[2]:
            return self.lease[:2]
        self.next_generation += 1
        entry = self.queue[0]
        token = Token(self.session, reader, entry.receipt, entry.tx, self.next_generation)
        self.lease = (entry, token, now+TTL)
        return entry, token
    def ack(self, reader, token, now):
        if self.lost or reader != TRUSTED or not self.lease: return False
        entry, existing, deadline = self.lease
        if now >= deadline or token != existing or token.reader != reader or token.session != self.session:
            return False
        if self.queue[0] != entry: return False
        self.queue.popleft()
        self.lease = None
        return True
    def die(self, owner_epoch):
        self.queue = deque(Entry(e.session,e.receipt,e.tx,e.endpoint,e.family,e.owner_epoch,True)
                           if e.owner_epoch == owner_epoch else e for e in self.queue)
        self.lease = None  # old live payload cannot be ACKed after tombstone conversion
    def stop(self):
        self.lost = True
        self.queue.clear()
        self.lease = None

class Worker:
    def __init__(self):
        self.journal = set()  # already-durable (session, receipt, tx, tombstone) records
        self.volatile = None
    def peek(self, k, now):
        self.volatile = k.peek(TRUSTED, now)
        return self.volatile
    def persist(self):
        if not self.volatile: return False
        e, _ = self.volatile
        self.journal.add((e.session, e.receipt, e.tx, e.tombstone))
        return True
    def ack(self, k, now):
        if not self.volatile: return False
        _, token = self.volatile
        return k.ack(TRUSTED,token,now)
    def restart(self):
        self.volatile = None


def scenario(family, n, cut, stage, ordering):
    k = Kernel(100+family, family)
    w = Worker()
    for i in range(1, n+1):
        must(k.observe(1000+i, 5000+i), 'observe')
    now = 1
    def process():
        nonlocal now
        must(w.peek(k,now), 'peek')
        if ordering == 'persist-ack':
            must(w.persist(), 'persist')
            must(w.ack(k,now), 'ack')
        else:
            must(w.ack(k,now), 'ack')
            must(w.persist(), 'persist')
        w.restart()
        now += 1
    for _ in range(cut-1): process()
    if stage != 'before-peek':
        must(w.peek(k,now), 'peek')
        if stage in ('after-first','after-second'):
            if ordering == 'persist-ack': must(w.persist(), 'persist')
            else: must(w.ack(k,now), 'ack')
        if stage == 'after-second':
            if ordering == 'persist-ack': must(w.ack(k,now), 'ack')
            else: must(w.persist(), 'persist')
    w.restart()  # reader worker only; kernel session + broker remain alive
    now += TTL + 1
    while k.queue:
        process()
    durable = sorted(e[1] for e in w.journal)
    missing = [i for i in range(1,n+1) if i not in durable]
    return dict(family=family,n=n,cut=cut,stage=stage,ordering=ordering,
                durable=durable,missing=missing,empty=not k.queue,lost=k.lost,
                tail_silent=bool(missing) and n in missing)

def matrix():
    for family in (4,6):
        for ordering in ('persist-ack','ack-persist'):
            for n in range(1,5):
                for cut in range(1,n+1):
                    for stage in ('before-peek','after-peek','after-first','after-second'):
                        yield scenario(family,n,cut,stage,ordering)

class Tests(unittest.TestCase):
    def test_all_persist_first_fully_recoverable(self):
        rows=list(matrix())
        self.assertEqual(len(rows),160)
        self.assertTrue(all(not x['missing'] for x in rows if x['ordering']=='persist-ack'))
        self.assertTrue(all(x['empty'] and not x['lost'] for x in rows))
    def test_ack_first_crash_after_ack_loses_exactly_one(self):
        rows=[x for x in matrix() if x['ordering']=='ack-persist']
        lost=[x for x in rows if x['missing']]
        self.assertEqual(len(lost),20)
        for x in lost:
            self.assertEqual(x['stage'],'after-first')
            self.assertEqual(x['missing'],[x['cut']])
    def test_stale_ack_expired_lease_and_pid_reuse(self):
        k=Kernel(104,4);self.assertTrue(k.observe(1,10))
        e,t=k.peek(TRUSTED,0)
        self.assertIsNone(k.peek(SIBLING,1))
        self.assertIsNone(k.peek(OTHER,1))
        self.assertFalse(k.ack(SIBLING,t,1))
        self.assertFalse(k.ack(TRUSTED,t,TTL))
        e2,t2=k.peek(TRUSTED,TTL)
        self.assertEqual(e,e2);self.assertNotEqual(t,t2)
        self.assertFalse(k.ack(TRUSTED,t,TTL))
        self.assertTrue(k.ack(TRUSTED,t2,TTL))
        self.assertFalse(k.ack(TRUSTED,t2,TTL))
    def test_tombstone_preserves_receipt_but_invalidates_live_lease(self):
        k=Kernel(106,6);k.observe(1,10,epoch=99)
        live,token=k.peek(TRUSTED,1)
        self.assertFalse(live.tombstone)
        k.die(99)
        self.assertFalse(k.ack(TRUSTED,token,2))
        dead,new_token=k.peek(TRUSTED,2)
        self.assertTrue(dead.tombstone)
        self.assertEqual(dead.receipt,live.receipt)
        self.assertEqual(dead.tx,live.tx)
        self.assertTrue(k.ack(TRUSTED,new_token,2))
    def test_broker_death_and_ssh_loss_terminal(self):
        for family in (4,6):
            k=Kernel(100+family,family);k.observe(1,10)
            _,t=k.peek(TRUSTED,1);k.stop()
            self.assertFalse(k.ack(TRUSTED,t,2))
            self.assertIsNone(k.peek(TRUSTED,2))
            self.assertFalse(k.observe(2,11))
    def test_transaction_and_endpoint_aba_terminal(self):
        for repeat in ('endpoint','tx'):
            k=Kernel(104,4);k.observe(100,900)
            self.assertFalse(k.observe(100 if repeat=='endpoint' else 101,
                                       901 if repeat=='endpoint' else 900))
            self.assertTrue(k.lost)
    def test_capacity_32_33_sticky(self):
        k=Kernel(104,4)
        for i in range(32):self.assertTrue(k.observe(100+i,900+i))
        self.assertFalse(k.observe(500,1500));self.assertTrue(k.lost)
        self.assertIsNone(k.peek(TRUSTED,1))
    def test_wrong_session_transaction_and_delivery_generation_denied(self):
        k=Kernel(104,4);k.observe(1,10)
        _,t=k.peek(TRUSTED,1)
        for wrong in (Token(105,t.reader,t.receipt,t.tx,t.delivery_generation),
                      Token(104,t.reader,t.receipt,999,t.delivery_generation),
                      Token(104,t.reader,t.receipt,t.tx,t.delivery_generation+1),
                      Token(104,SIBLING,t.receipt,t.tx,t.delivery_generation)):
            self.assertFalse(k.ack(TRUSTED,wrong,1))
        self.assertTrue(k.ack(TRUSTED,t,1))

if __name__ == '__main__':
    if '--matrix' in sys.argv:
        for row in matrix():print(json.dumps(row,sort_keys=True,separators=(',',':')))
    else:unittest.main(argv=[sys.argv[0]])
