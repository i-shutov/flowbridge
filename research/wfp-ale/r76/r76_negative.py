"""R76 deterministic offline event-correlation counterexamples. stdlib only."""
import hashlib,itertools,json,sys,unittest
MODES=('normal','circular_overwrite','disabled','reboot','enum_snapshot_before_event')

def score(f,p,a,t,w,fl,e,s,d,m,o,direct):
    n=int(p==6 and a and t and w and fl and d)
    actual=int(n and e and s and o)
    return (n,actual,int(n and not actual),int(n and direct),int(m!='normal'),0,0)

def run():
    c=dict(total=0,naive=0,actual=0,false_join=0,false_no_direct=0,missing_history=0,claimed_identity=0,claimed_no_direct=0,v4=0,v6=0,tcp=0,udp=0)
    h=hashlib.sha256()
    for w in itertools.product((4,6),(6,17),(0,1),(0,1),(0,1),(0,1),(0,1),(0,1),(0,1),MODES,(0,1),(0,1)):
        ans=score(*w);c['total']+=1;c['v'+str(w[0])]+=1;c['tcp' if w[1]==6 else 'udp']+=1
        for key,val in zip(('naive','actual','false_join','false_no_direct','missing_history','claimed_identity','claimed_no_direct'),ans):c[key]+=val
        h.update(('|'.join(map(str,w+ans))+'\n').encode())
    c['sha256']=h.hexdigest();return c
class Counterexamples(unittest.TestCase):
    def test_epoch_reuse(self):
        self.assertEqual(score(4,6,1,1,1,1,0,1,1,'normal',1,0)[2],1)
    def test_socket_mismatch(self):
        self.assertEqual(score(6,6,1,1,1,1,1,0,1,'normal',1,0)[2],1)
    def test_direct_sibling(self):
        self.assertEqual(score(4,6,1,1,1,1,1,1,1,'normal',1,1)[3],1)
    def test_missing_event_not_proof(self):
        self.assertEqual(score(4,6,1,1,1,1,1,1,0,'reboot',1,0)[5:],(0,0))
    def test_matrix(self):
        c=run();self.assertEqual((c['total'],c['naive'],c['false_join'],c['claimed_identity']),(10240,160,140,0))
if __name__=='__main__':
    if '--oracle' in sys.argv:print(json.dumps(run(),sort_keys=True,separators=(',',':')))
    else:unittest.main()
