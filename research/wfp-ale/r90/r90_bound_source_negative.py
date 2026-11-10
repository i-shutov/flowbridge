"""R90 source-conditional negative matrix; no socket, OS, WFP or network access.

This models only local_supported() in pinned redirect.rs and the immediate
block() branch. It does not claim an address was observed in a real classify.
"""
import hashlib
import ipaddress
import unittest

V4 = (
    ('unspecified','0.0.0.0',0,True),
    ('broker_exact','127.0.0.1',0,True),
    ('other_loopback','127.0.0.2',0,False),
    ('bound_rfc1918_10','10.9.0.4',0,False),
    ('bound_rfc1918_172','172.20.3.2',0,False),
    ('bound_rfc1918_192','192.168.1.10',0,False),
    ('bound_linklocal','169.254.6.8',0,False),
)
V6 = (
    ('unspecified','::',0,True),
    ('broker_exact','::1',0,True),
    ('other_loopback','::2',0,False),
    ('bound_ula','fd12::9',0,False),
    ('bound_linklocal_scoped','fe80::4',4,False),
    ('bound_global','2001:db8::10',0,False),
    ('scoped_loopback','::1',4,False),
)
REMOTES = {'v4': ('8.8.8.8', '10.3.2.1'), 'v6': ('2606:4700:4700::1111', 'fd13::1')}


def source_supported(source, scope_id=0):
    """Reproduce exactly the source's normalized SOCKADDR_STORAGE predicate."""
    ip = ipaddress.ip_address(source)
    raw = bytearray(128)
    raw[0:2] = (2 if ip.version == 4 else 23).to_bytes(2, 'little')
    if ip.version == 4:
        raw[4:8] = ip.packed
        return raw[4:8] == bytes(4) or raw[4:8] == bytes((127,0,0,1))
    raw[8:24] = ip.packed
    raw[24:28] = scope_id.to_bytes(4, 'little')
    return raw[24:28] == bytes(4) and (raw[8:24] == bytes(16)
        or raw[8:24] == bytes(15) + b'\x01')


def rows():
    for family, group in (('v4', V4), ('v6', V6)):
        for name, local, scope_id, expected in group:
            for remote in REMOTES[family]:
                verdict = ('LOCAL_SOURCE_ADMITTED_TO_LATER_GATES'
                           if source_supported(local,scope_id)
                           else 'BLOCK_BEFORE_TICKET')
                yield (family,name,local,scope_id,remote,verdict)


def serialized():
    return ''.join('|'.join(map(str,row))+'\n' for row in rows())


class BoundSourceTests(unittest.TestCase):
    def test_exact_source_logic_all_cases(self):
        for group in (V4,V6):
            for name, local, scope, expected in group:
                with self.subTest(name=name,local=local,scope=scope):
                    self.assertEqual(source_supported(local,scope),expected)

    def test_bound_ip_rejection_in_both_families(self):
        for source in ['10.9.0.4','172.20.3.2','192.168.1.10','169.254.6.8',
                       'fd12::9','2001:db8::10']:
            with self.subTest(source=source):
                self.assertFalse(source_supported(source))

    def test_nonexact_loopback_and_scope(self):
        self.assertFalse(source_supported('127.0.0.2'))
        self.assertFalse(source_supported('::2'))
        self.assertFalse(source_supported('::1',4))

    def test_remote_does_not_alter_local_predicate(self):
        output=list(rows())
        self.assertEqual(len(output),28)
        self.assertEqual(sum(r[-1]=='BLOCK_BEFORE_TICKET' for r in output),20)
        self.assertEqual(sum(r[-1]=='LOCAL_SOURCE_ADMITTED_TO_LATER_GATES' for r in output),8)

    def test_cannot_prove_real_bind_reachability(self):
        # These are conditional callback inputs, not a physical WFP execution.
        self.assertEqual(REMOTES['v4'][0],'8.8.8.8')
        self.assertIn('BLOCK_BEFORE_TICKET',serialized())

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(BoundSourceTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    print('R90_ROWS='+str(len(list(rows()))))
    print('R90_SHA256='+hashlib.sha256(serialized().encode('utf-8')).hexdigest())
    if not result.wasSuccessful():raise SystemExit(1)
