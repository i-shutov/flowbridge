#!/usr/bin/env python3
"""Pure standard-library R19 FBR3 projection collision proof, no OS access."""
import hashlib, json, struct, unittest
from pathlib import Path
from dataclasses import dataclass, replace

PINS = {
 'kernel/src/handoff.rs': 'e1d17217db50362ba9c4efc83af820b6beb094cf',
 'kernel/src/redirect.rs': 'a093f049d162987981a957aac90db1014bc6ff09',
 'kernel/src/lib.rs': '53f5ce6faa0f9f591974287f38ea890cafeb0dd2',
}
@dataclass(frozen=True)
class Flow:
    family: int = 4
    pid: int = 111
    epoch: int = 222
    start_key: int = 333
    endpoint: int = 444
    owner_generation: int = 1
    sequence: int = 1
    stamp: int = 9876543
    port: int = 443
    destination: bytes = bytes([203,0,113,8])+bytes(12)
    compartment: int = 1
    parent_endpoint: int = 0
    remote_scope: int = 0

def source_gate(root: Path)->str:
    """Fail closed on missing or changed source; root is kernel-r19/kernel/src."""
    sources={}
    for name,want in PINS.items():
        data=(root / name.removeprefix('kernel/src/')).read_bytes()
        got=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if got!=want: raise RuntimeError('SOURCE_SHA_MISMATCH:'+name+':'+got)
        sources[name]=data.decode('utf-8')
    h,r,lib=(sources['kernel/src/'+n] for n in ('handoff.rs','redirect.rs','lib.rs'))
    for needle in ('pub struct Origin { pub pid:u64, pub epoch:u64, pub key:u64, pub endpoint:u64, pub generation:u64 }',
                   'pub struct Context(pub [u8; LEN]);','pub const LEN: usize = 128;'):
        if needle not in h:raise RuntimeError('HANDOFF_WIRE_CHANGED:'+needle)
    for needle in ('Origin{pid:o.pid,epoch:o.epoch,key:o.start_key,endpoint:m.transportEndpointHandle,generation}',
                   'route.book.attest(identity,original_destination,now())'):
        if needle not in r:raise RuntimeError('AUTH_ORIGIN_CHANGED:'+needle)
    if 'FWPS_METADATA_FIELD_PROCESS_ID' not in r or 'mod handoff;' not in lib:
        raise RuntimeError('SOURCE_CLOSURE_CHANGED')
    return 'FULL_SOURCE_GATE_PASS 3/3'

def encode(f: Flow)->bytes:
    assert f.family in (4,6) and len(f.destination)==16
    b=bytearray(128)
    b[:8]=b'FBR3\x01\x00\x80\x00'; b[8:24]=bytes.fromhex('00112233445566778899aabbccddeeff')
    for off,val in ((24,f.sequence),(32,f.pid),(40,f.epoch),(48,f.start_key),
                    (56,f.endpoint),(64,f.owner_generation),(96,f.stamp)):
        struct.pack_into('<Q',b,off,val)
    b[72]=f.family; b[73]=6; struct.pack_into('!H',b,74,f.port)
    b[80:96]=f.destination
    return bytes(b)

def fixture(family):
    if family==4:return Flow()
    return Flow(family=6,destination=bytes.fromhex('20010db8000000000000000000000008'))

def matrix():
    cases=[]
    for family in (4,6):
        base=fixture(family)
        for field,values in (
            ('compartment',(2,7,101)),
            ('parent_endpoint',(2,777,1<<40)),
            ('remote_scope',(2,7,101)),
        ):
            for value in values:
                shifted=replace(base,**{field:value})
                cases.append({'family':family,'dimension':field,'value':value,
                              'same_context':encode(base)==encode(shifted)})
    return cases

class ProjectionTests(unittest.TestCase):
    def test_original_128_byte_layout_both_families(self):
        for family in (4,6):
            b=encode(fixture(family))
            self.assertEqual(len(b),128)
            self.assertEqual(b[:8],b'FBR3\x01\x00\x80\x00')
            self.assertEqual(b[76:80],bytes(4))
            self.assertEqual(b[104:],bytes(24))
            self.assertEqual(b[72],family)
    def test_all_unbound_dimensions_project_identically(self):
        self.assertEqual(len(matrix()),18)
        self.assertTrue(all(x['same_context'] for x in matrix()))
    def test_bound_dimensions_change_projected_context(self):
        for family in (4,6):
            base=fixture(family)
            for field in ('pid','epoch','start_key','endpoint','owner_generation','sequence','stamp','port'):
                self.assertNotEqual(encode(base),encode(replace(base,**{field:getattr(base,field)+1})),field)
            self.assertNotEqual(encode(base),encode(replace(base,destination=base.destination[:15]+bytes([base.destination[15]^1]))))
    def test_families_differ(self):
        self.assertNotEqual(encode(fixture(4)),encode(fixture(6)))
    def test_do_not_claim_native_ambiguity(self):
        left=fixture(6);right=replace(left,compartment=17,parent_endpoint=91)
        self.assertEqual(encode(left),encode(right))
        self.assertNotEqual((left.compartment,left.parent_endpoint),(right.compartment,right.parent_endpoint))

if __name__=='__main__':
    import sys
    if len(sys.argv)==3 and sys.argv[1]=='--source-gate':
        print(source_gate(Path(sys.argv[2])))
    elif len(sys.argv)==2 and sys.argv[1]=='--matrix':
        print(json.dumps(matrix(),sort_keys=True,separators=(',',':')))
    else: unittest.main()
