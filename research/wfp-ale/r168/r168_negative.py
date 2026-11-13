#!/usr/bin/env python3
"""Offline deterministic R168 TOTAL-deadline to global-STOP negative cases."""
import hashlib, itertools, json, pathlib, sys, unittest
PINS = {
    'trusted-ssh-r37/src/lib.rs': 'c6d8c8746fac45073c11557de893164e49d830eb',
    'broker.rs': '6163e84aea08ddde7e51a7fb94ccb6d68ae951fb',
    'broker_windows.rs': '329ef14b63e70226bfad7372b0014559213abd04',
    'kernel/src/redirect.rs': 'a093f049d162987981a957aac90db1014bc6ff09',
    'kernel/src/handoff.rs': 'e1d17217db50362ba9c4efc83af820b6beb094cf',
}
def gate(root):
    paths = {}
    for p, expected in PINS.items():
        data = (root / 'research/wfp-ale/kernel-r19' / p).read_bytes()
        got = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if got != expected: raise ValueError('source mismatch '+p)
        paths[p] = data.decode('utf-8')
    assert 'Duration::from_secs(60), tokio::io::copy_bidirectional(left, right)' in paths['trusted-ssh-r37/src/lib.rs']
    assert 'if result.is_err(){revoke(&s,&notify);}' in paths['broker.rs']
    assert 'let stopped=d.command(handoff::STOP,&[]);' in paths['broker.rs']
    assert 'if code==h::STOP{lose();return super::SUCCESS;}' in paths['kernel/src/redirect.rs']
    assert 'r.armed=false;r.book.kill();' in paths['kernel/src/redirect.rs']
    assert 'relay_over_pinned_ssh' in paths['broker_windows.rs']
    return len(paths)
def decide(t, eof, activity, ping, workers):
    if not ping: outcome = 'KERNEL_LOSS'
    elif eof is not None and eof < 60 and eof <= t: outcome = 'CLEAN_EOF'
    elif t > 60: outcome = 'COPY_TIMEOUT'
    else: outcome = 'COPY_PENDING'
    fatal = outcome in ('COPY_TIMEOUT', 'KERNEL_LOSS')
    return {'outcome':outcome,'revoke':fatal,'sibling_canceled':workers-1 if fatal else 0,'stop_expected':fatal}
def matrix():
    return [{'horizon':t,'eof_at':e,'activity':a,'ping':p,'workers':w,'result':decide(t,e,a,p,w)}
            for t,e,a,p,w in itertools.product((5,30,59,61,75,120),(None,2,10,40,90),('idle','streaming'),(False,True),(1,2,3))]
class Tests(unittest.TestCase):
    def test_both_active_and_idle_timeout(self):
        for a in ('streaming','idle'): self.assertEqual(decide(75,None,a,True,2)['outcome'],'COPY_TIMEOUT')
    def test_total_not_idle_timer(self): self.assertEqual(decide(75,None,'streaming',True,1),decide(75,None,'idle',True,1))
    def test_clean_eof_does_not_revoke(self): self.assertFalse(decide(120,40,'streaming',True,2)['revoke'])
    def test_predeadline_remains_pending(self): self.assertEqual(decide(59,None,'streaming',True,2)['outcome'],'COPY_PENDING')
    def test_long_lived_one_revokes_other_two(self): self.assertEqual(decide(75,None,'streaming',True,3)['sibling_canceled'],2)
    def test_kernel_loss_is_independent(self): self.assertEqual(decide(5,None,'idle',False,2)['outcome'],'KERNEL_LOSS')
    def test_idle_reset_mutant_disagrees(self): self.assertNotEqual('COPY_PENDING',decide(75,None,'streaming',True,1)['outcome'])
if __name__ == '__main__':
    if len(sys.argv)==2 and sys.argv[1]=='--matrix':print(json.dumps(matrix(),separators=(',',':')))
    elif len(sys.argv)==3 and sys.argv[1]=='--source-gate':print('source_gate',gate(pathlib.Path(sys.argv[2])))
    else:unittest.main()
