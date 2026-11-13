#!/usr/bin/env python3
"""Independent offline semantic projection tests. NOT native WFP or Rust."""
import json, sys, unittest
from dataclasses import dataclass

@dataclass(frozen=True)
class Origin:
    pid:int=101
    epoch:int=202
    key:int=303
    endpoint:int=404
    generation:int=1

def witness(o, ledger_session, receipt, family, appid):
    return (ledger_session,receipt,o.endpoint,o.pid,o.epoch,o.key,
            o.generation,family,15,6,appid)

def context(o,book_session,sequence,family,ip,port,issued_at):
    return (book_session,sequence,o.pid,o.epoch,o.key,o.endpoint,
            o.generation,family,6,ip,port,issued_at)

def separate_counter_trace(prior_issue):
    o=Origin()
    book_seq=0
    tombstones=set()
    if prior_issue:
        assert 405!=o.endpoint and 405 not in tombstones
        tombstones.add(405)
        book_seq+=1
    assert o.endpoint not in tombstones
    tombstones.add(o.endpoint)
    book_seq+=1
    return (witness(o,93,1,4,'selected.exe'),
            context(o,'a'*32,book_seq,4,'192.0.2.1',443,100),
            len(tombstones))

def matrix():
    o=Origin()
    result=[]
    for family,first,second in [(4,'192.0.2.1','192.0.2.2'),
                                (6,'2001:db8::1','2001:db8::2')]:
        for ledger_session in [1,2,65535]:
            for receipt in [1,5,33]:
                for kind in ['destination','port','sequence','book_session','issued_at']:
                    w1=witness(o,ledger_session,receipt,family,'selected.exe')
                    w2=witness(o,ledger_session,receipt,family,'selected.exe')
                    c1=context(o,'a'*32,1,family,first,443,100)
                    args={'destination':('a'*32,1,second,443,100),
                          'port':('a'*32,1,first,8443,100),
                          'sequence':('a'*32,2,first,443,100),
                          'book_session':('b'*32,1,first,443,100),
                          'issued_at':('a'*32,1,first,443,101)}
                    c2=context(o,args[kind][0],args[kind][1],
                               family,args[kind][2],args[kind][3],args[kind][4])
                    result.append({'case':f'{family}-{ledger_session}-{receipt}-{kind}',
                                   'context_equal':c1==c2,'context_fields':12,
                                   'witness_equal':w1==w2,'witness_fields':11})
    return result

class Tests(unittest.TestCase):
    def test_destination(self):
        for f,a,b in [(4,'192.0.2.1','192.0.2.2'),
                       (6,'2001:db8::1','2001:db8::2')]:
            o=Origin()
            self.assertEqual(witness(o,5,7,f,'selected.exe'),
                             witness(o,5,7,f,'selected.exe'))
            self.assertNotEqual(context(o,'1'*32,1,f,a,443,1),
                                context(o,'1'*32,1,f,b,443,1))
    def test_sequence(self):
        o=Origin()
        self.assertNotEqual(context(o,'a'*32,1,4,'192.0.2.1',443,1),
                            context(o,'a'*32,2,4,'192.0.2.1',443,1))
        self.assertNotEqual(witness(o,8,1,4,'x'),witness(o,8,2,4,'x'))
    def test_sessions(self):
        o=Origin()
        self.assertNotEqual(context(o,'a'*32,1,4,'192.0.2.1',443,1),
                            context(o,'b'*32,1,4,'192.0.2.1',443,1))
        self.assertEqual(witness(o,1,1,4,'x'),witness(o,1,1,4,'x'))
    def test_origin_is_preserved(self):
        a=Origin()
        b=Origin(pid=102)
        self.assertNotEqual(witness(a,1,1,4,'x'),witness(b,1,1,4,'x'))
        self.assertNotEqual(context(a,'a'*32,1,4,'192.0.2.1',443,1),
                            context(b,'a'*32,1,4,'192.0.2.1',443,1))
    def test_alternate_tombstone_safe_histories(self):
        w1,c1,n1=separate_counter_trace(False)
        w2,c2,n2=separate_counter_trace(True)
        self.assertEqual(w1,w2)
        self.assertNotEqual(c1,c2)
        self.assertEqual((c1[1],c2[1],n1,n2),(1,2,1,2))
    def test_all_negative_cases(self):
        rows=matrix()
        self.assertEqual(len(rows),90)
        self.assertTrue(all(x['witness_equal'] and not x['context_equal'] for x in rows))

if __name__=='__main__':
    if '--matrix' in sys.argv:
        for row in matrix():
            print(json.dumps(row,sort_keys=True,separators=(',',':')))
    else:unittest.main()
