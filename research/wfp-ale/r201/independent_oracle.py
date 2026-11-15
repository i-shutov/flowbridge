"""R201 independent Python state oracle for selected-process bounded accounting.
Never loads Rust, WFP, driver, API, or network. Independent truth-table verification.
"""
from dataclasses import dataclass
import unittest

SEL, BRK = r'\device\volume1\selected.exe', r'\device\volume1\broker.exe'

@dataclass(frozen=True)
class Identity:
    pid: int
    epoch: int
    start: int
    ptr: int
    file: int
    exe: str
    @property
    def key(self): return self.pid, self.epoch, self.start

def make(pid, exe=SEL): return Identity(pid,pid+100,pid+900,pid+1,pid+2,exe)

class Oracle:
    def __init__(self, cap=4, history=32, endpoint_limit=32):
        self.live = {}
        self.history = set()
        self.ep_seen = set()
        self.tickets = {}
        self.cap, self.hist_cap, self.ep_cap = cap, history, endpoint_limit
        self.generation = 0
        self.stopped = False
    def stop(self):
        self.stopped=True
        self.tickets.clear()
        return 'STOP'
    def born(self, o):
        if self.stopped: return 'STOP'
        if o.pid in self.live: return self.stop()
        if o.exe not in (SEL, BRK): return 'IGNORE'
        if (not all((o.pid,o.epoch,o.start,o.ptr,o.file)) or o.key in self.history or
            len(self.history) == self.hist_cap or len(self.live) == self.cap): return self.stop()
        self.generation += 1
        self.live[o.pid] = (o,self.generation)
        self.history.add(o.key)
        return 'OK'
    def death(self,pid,ptr):
        if self.stopped: return 'STOP'
        found = self.live.get(pid)
        if found is None: return 'IGNORE'
        if found[0].ptr != ptr: return self.stop()
        o,gen = self.live.pop(pid)
        self.tickets={k:v for k,v in self.tickets.items() if v[1] != gen}
        return self.stop() if o.exe == BRK else 'OK'
    def issue(self,o,ep,family,proto,dst):
        if self.stopped: return 'STOP'
        if not ep or family not in (4,6) or proto != 6 or not dst:return 'DENY'
        live = self.live.get(o.pid)
        if not live or live[0] != o or o.exe != SEL:return 'DENY'
        if not any(v[0].exe == BRK for v in self.live.values()):return 'DENY'
        if ep in self.ep_seen or len(self.ep_seen)==self.ep_cap:return self.stop()
        self.ep_seen.add(ep)
        self.tickets[ep] = (o.key,live[1],family,dst,False)
        return 'OK'
    def attest(self,o,ep,family,dst,original,redirected,reauth):
        if self.stopped:return 'STOP'
        live=self.live.get(o.pid); ticket=self.tickets.get(ep)
        if not live or live[0]!=o or o.exe!=SEL or original!=SEL or not redirected or reauth or ticket is None:return 'DENY'
        if ticket!=(o.key,live[1],family,dst,False):return 'DENY'
        self.tickets[ep]=(o.key,live[1],family,dst,True)
        return 'OK'
    def claim(self,o,ep):
        if self.stopped:return 'STOP'
        ticket=self.tickets.pop(ep,None)
        live=self.live.get(o.pid)
        if not ticket or not live or live[0]!=o or o.exe!=SEL:return 'DENY'
        return 'OK' if ticket[0]==o.key and ticket[1]==live[1] and ticket[4] else 'DENY'

class Negative(unittest.TestCase):
    def test_unrelated_global_churn(self):
        o=Oracle(); a=make(1);o.born(a);o.born(make(2,BRK))
        for pid in range(100,10100):self.assertEqual(o.born(make(pid,'other')),'IGNORE')
        self.assertEqual((len(o.live),len(o.history),o.stopped),(2,2,False))
    def test_stale_incarnation_after_reuse(self):
        o=Oracle();a=make(1);o.born(a);o.death(1,a.ptr)
        b=Identity(1,a.epoch+1,a.start+1,a.ptr+10,a.file+10,SEL)
        self.assertEqual(o.born(b),'OK');self.assertEqual(o.born(a),'STOP')
    def test_wrong_process_death_and_live_collision(self):
        for operation in ('death','birth'):
            o=Oracle();o.born(make(1))
            verdict=o.death(1,999) if operation=='death' else o.born(make(1,'other'))
            self.assertEqual(verdict,'STOP')
    def test_tuple_only_not_authority_and_one_shot(self):
        o=Oracle();a=make(1);o.born(a);o.born(make(2,BRK))
        self.assertEqual(o.issue(a,91,4,6,'host:443'),'OK')
        self.assertEqual(o.attest(a,91,4,'host:443',SEL,True,False),'OK')
        o.death(1,a.ptr)
        b=Identity(1,a.epoch+1,a.start+1,a.ptr+10,a.file+10,SEL);o.born(b)
        self.assertEqual(o.claim(a,91),'DENY')
        self.assertEqual(o.issue(b,92,4,6,'host:443'),'OK')
        self.assertEqual(o.attest(b,92,4,'host:443',SEL,True,False),'OK')
        self.assertEqual(o.claim(b,92),'OK');self.assertEqual(o.claim(b,92),'DENY')
    def test_endpoint_aba_fails_closed(self):
        o=Oracle();a=make(1);o.born(a);o.born(make(2,BRK));o.issue(a,91,4,6,'host');o.attest(a,91,4,'host',SEL,True,False);o.claim(a,91)
        self.assertEqual(o.issue(a,91,4,6,'host'),'STOP')
    def test_appid_reauth_ipv6_and_udp(self):
        o=Oracle();a=make(1);o.born(a);o.born(make(2,BRK))
        self.assertEqual(o.issue(a,77,6,6,'[2001:db8::1]:443'),'OK')
        self.assertEqual(o.attest(a,77,6,'[2001:db8::1]:443',BRK,True,False),'DENY')
        self.assertEqual(o.attest(a,77,6,'[2001:db8::1]:443',SEL,True,True),'DENY')
        self.assertEqual(o.attest(a,77,6,'[2001:db8::1]:443',SEL,True,False),'OK')
        self.assertEqual(o.claim(a,77),'OK')
        self.assertEqual(o.issue(a,88,4,17,'DNS:53'),'DENY')
    def test_missing_broker_and_sibling_cannot_poison_endpoint(self):
        o=Oracle();a=make(1);o.born(a)
        self.assertEqual(o.issue(a,91,4,6,'host'),'DENY')
        o.born(make(2,BRK));self.assertEqual(o.issue(a,91,4,6,'host'),'OK')
        self.assertEqual(o.issue(make(7,'other'),91,4,6,'host'),'DENY')
        self.assertFalse(o.stopped)
        self.assertEqual(o.attest(a,91,4,'host',SEL,True,False),'OK')
        self.assertEqual(o.claim(a,91),'OK')
    def test_foreign_sibling_and_health(self):
        o=Oracle();b=make(1,'other');self.assertEqual(o.born(b),'IGNORE');self.assertEqual(o.issue(b,8,4,6,'host'),'DENY')
        o.stop();self.assertEqual(o.born(make(4)),'STOP')
    def test_broker_exit_and_history_bound(self):
        o=Oracle();b=make(2,BRK);o.born(b);self.assertEqual(o.death(2,b.ptr),'STOP')
        o=Oracle(history=1);a=make(1);o.born(a);o.death(1,a.ptr);self.assertEqual(o.born(make(3)),'STOP')

if __name__ == '__main__':unittest.main(verbosity=2)
