#!/usr/bin/env python3
"""R207 source-conditional negative test. No Windows, network, WFP or driver calls."""
from pathlib import Path
from hashlib import sha1
import sys
import unittest

class Book:
    def __init__(self, strict=False):
        self.strict = strict
        self.slots = {}
        self.stopped = False

    def issue(self, endpoint, family, epoch=1):
        assert endpoint not in self.slots
        self.slots[endpoint] = dict(family=family, epoch=epoch, live=True, seen=False)

    def auth(self, endpoint, family, epoch=1, reauth=False, metadata=True, original=True):
        slot = self.slots.get(endpoint)
        valid = (slot is not None and slot['live'] and not slot['seen']
                 and not reauth and metadata and original and
                 slot['family'] == family and slot['epoch'] == epoch)
        if not valid:
            if self.strict and slot is not None:
                slot['live'] = False
            return 'BLOCK'
        slot['seen'] = True
        return 'MODEL_AUTH'

    def claim(self, endpoint, epoch=1):
        slot = self.slots.get(endpoint)
        if self.stopped or slot is None:
            return 'DENY'
        valid = slot['live'] and slot['seen'] and slot['epoch'] == epoch
        slot['live'] = False
        return 'MODEL_CLAIM' if valid else 'DENY'

class Negative(unittest.TestCase):
    def test_stale_claim_after_reauth_both_families(self):
        for family in (4,6):
            for strict in (False, True):
                b = Book(strict); b.issue(7, family)
                self.assertEqual(b.auth(7, family), 'MODEL_AUTH')
                self.assertEqual(b.auth(7, family, reauth=True), 'BLOCK')
                self.assertEqual(b.claim(7), 'DENY' if strict else 'MODEL_CLAIM')

    def test_reauth_before_initial_does_not_retire(self):
        for strict in (False, True):
            b = Book(strict); b.issue(7,4)
            self.assertEqual(b.auth(7,4,reauth=True),'BLOCK')
            self.assertEqual(b.auth(7,4),'BLOCK' if strict else 'MODEL_AUTH')
            self.assertEqual(b.claim(7),'DENY' if strict else 'MODEL_CLAIM')

    def test_malformed_after_valid_keeps_old_evidence(self):
        for bad in ('metadata','original'):
            for strict in (False, True):
                b=Book(strict); b.issue(7,4); b.auth(7,4)
                kw={bad:False}
                self.assertEqual(b.auth(7,4,**kw),'BLOCK')
                self.assertEqual(b.claim(7),'DENY' if strict else 'MODEL_CLAIM')

    def test_endpoint_isolation_and_terminal_claim(self):
        b=Book(True); b.issue(7,4); b.auth(7,4)
        self.assertEqual(b.auth(8,4,reauth=True),'BLOCK')
        self.assertEqual(b.claim(7),'MODEL_CLAIM')
        self.assertEqual(b.claim(7),'DENY')

    def test_epoch_reuse_cannot_claim(self):
        b=Book(); b.issue(7,6,epoch=23); b.auth(7,6,epoch=23)
        self.assertEqual(b.claim(7,epoch=24),'DENY')
        self.assertEqual(b.claim(7,epoch=23),'DENY')

    def test_loss_revokes(self):
        b=Book(); b.issue(7,4); b.auth(7,4); b.stopped=True
        self.assertEqual(b.claim(7),'DENY')

def source_gate():
    root=Path(__file__).resolve().parents[1]
    specs={
        'redirect':('kernel-r19/kernel/src/redirect.rs','a093f049d162987981a957aac90db1014bc6ff09'),
        'handoff':('kernel-r19/kernel/src/handoff.rs','e1d17217db50362ba9c4efc83af820b6beb094cf'),
        'ledger':('r201/selective_ledger.rs','bc4c02daf2f09609cfa11b595d842e5ad2608625'),
    }
    code={}
    for name,(path,want) in specs.items():
        data=(root/path).read_bytes()
        got=sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        assert got==want,(name,got,want)
        code[name]=data.decode()
    a,b,c=code['redirect'],code['handoff'],code['ledger']
    assertions=[
        'bits & (0x0000_0004|0x0200_0000)!=0{return false;}' in a,
        'if !auth_check(values,meta){block(out);return;}' in a,
        'route.book.attest(identity,original_destination,now())' in a,
        'book.retire(' not in a.split('pub unsafe fn auth_classify(',1)[1],
        'slot.auth_seen=true;' in b,
        'if !s.auth_seen || s.context!=context' in b,
        'reauthorize' not in b.split('pub fn take(',1)[1].split('pub fn kill(',1)[0],
        'if !redirected || reauthorize || original_appid != self.pins.selected {return Decision::Denied;}' in c,
    ]
    assert all(assertions),assertions
    print('Pinned Rust source structural gates 8/8 PASS (NOT kernel proof)')

if __name__=='__main__':
    if '--source' in sys.argv:
        source_gate()
        sys.argv.remove('--source')
    unittest.main(verbosity=2)
