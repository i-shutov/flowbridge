"""R75 negative oracle: synthetic, no WFP/Windows/network calls."""
import hashlib,itertools,json,sys,unittest
EV=('absent','authenticated','replay','wrong_epoch','spoofed')
SZ=(0,1,65536,65537,1048576,1048577)
def judge(family,origin,event,size,supported,pid_reuse,tuple_reuse):
    # Hidden origin, PID reuse and tuple reuse MUST NOT influence admission.
    return ('KERNEL_EVENT_STOP' if event=='authenticated' else 'SOCKET_DROP',
            int(supported and 0<size<=65536),int(supported and 0<size<=1048576))
def report():
    h=hashlib.sha256();c=dict(total=0,identical_observation_pairs=0,
      selected_lost_event=0,unrelated_event_stop=0,fixed_size_fit=0,
      bounded_size_fit=0,size_recoverable=0,v4=0,v6=0)
    for f,o,e,n,s,p,t in itertools.product((4,6),('selected','foreign'),EV,SZ,(0,1),(0,1),(0,1)):
        d=judge(f,o,e,n,s,p,t);c['total']+=1;c['v'+str(f)]+=1
        c['fixed_size_fit']+=d[1];c['bounded_size_fit']+=d[2]
        c['size_recoverable']+=d[2] and not d[1]
        c['selected_lost_event']+=o=='selected' and e=='absent'
        c['unrelated_event_stop']+=o=='foreign' and e=='authenticated'
        h.update(f'{f}|{o}|{e}|{n}|{s}|{p}|{t}|{d[0]}|{d[1]}|{d[2]}\n'.encode())
    c['identical_observation_pairs']=c['total']//2;c['sha256']=h.hexdigest()
    return c
class Negative(unittest.TestCase):
    def test_same_socket_observation(self):
        for f in (4,6):
            self.assertEqual(judge(f,'selected','absent',128,1,0,0),judge(f,'foreign','absent',128,1,0,0))
    def test_pid_reuse_no_authority(self):
        self.assertEqual(judge(4,'selected','absent',128,1,0,0),judge(4,'selected','absent',128,1,1,0))
    def test_tuple_reuse_no_authority(self):
        self.assertEqual(judge(6,'selected','absent',128,1,0,0),judge(6,'selected','absent',128,1,0,1))
    def test_spoof_replay_stale_ignored(self):
        for e in EV:
            self.assertEqual(judge(4,'selected',e,128,1,0,0)[0], 'KERNEL_EVENT_STOP' if e=='authenticated' else 'SOCKET_DROP')
    def test_global_event_not_socket_witness(self):
        self.assertEqual(judge(4,'foreign','authenticated',128,1,0,0)[0],'KERNEL_EVENT_STOP')
    def test_zero_records(self): self.assertEqual(judge(4,'selected','absent',0,1,0,0)[1:],(0,0))
    def test_fixed_boundary(self): self.assertEqual(judge(4,'selected','absent',65536,1,0,0)[1:],(1,1))
    def test_recoverable_boundary(self): self.assertEqual(judge(4,'selected','absent',65537,1,0,0)[1:],(0,1))
    def test_bounded_last(self): self.assertEqual(judge(6,'selected','absent',1048576,1,0,0)[1:],(0,1))
    def test_oversized(self): self.assertEqual(judge(6,'selected','absent',1048577,1,0,0)[1:],(0,0))
    def test_unsupported(self):
        for n in SZ:self.assertEqual(judge(4,'foreign','absent',n,0,0,0)[1:],(0,0))
    def test_cross_family(self):
        self.assertEqual(judge(4,'selected','absent',65537,1,0,0),judge(6,'selected','absent',65537,1,0,0))
    def test_truth_cannot_promote(self):
        for o in ('selected','foreign'):
            self.assertEqual(judge(4,o,'absent',65537,1,0,0)[0],'SOCKET_DROP')
    def test_ssh_loss_not_proved(self): self.assertEqual(judge(4,'selected','absent',128,1,0,0)[0],'SOCKET_DROP')
    def test_matrix(self):
        x=report();self.assertEqual(x['total'],960);self.assertEqual(x['v4'],480)
        self.assertEqual(x['bounded_size_fit']-x['fixed_size_fit'],x['size_recoverable'])
if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--oracle':print(json.dumps(report(),sort_keys=True))
    else:unittest.main()
