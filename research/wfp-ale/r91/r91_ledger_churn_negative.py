"""R91 source-conditional ledger saturation; no OS or socket calls."""
import hashlib
import unittest

CAP=256

class Ledger:
    def __init__(self):
        self.owners=[]
        self.lost=False
    def born(self,pid):
        if self.lost: return 'Lost'
        if pid in (p for p,live in self.owners):
            self.owners=[(p,False if p==pid else live) for p,live in self.owners]
            self.lost=True
            return 'ReusedPid'
        if len(self.owners)==CAP:
            self.lost=True
            return 'Full'
        self.owners.append((pid,True))
        return 'OK'
    def died(self,pid):
        for i,(p,live) in enumerate(self.owners):
            if p==pid: self.owners[i]=(p,False);break
    def lookup(self,pid):
        return not self.lost and any(p==pid and live for p,live in self.owners)
    def live(self):return sum(live for _,live in self.owners)

def record(s,step,code,l,selected):
    return (s,step,code,len(l.owners),l.live(),int(l.lost),int(l.lookup(selected)))

def scenario_rows():
    x=Ledger(); s='selected-survives-churn'; selected=1
    yield record(s,'selected-birth',x.born(1),x,selected)
    for pid in range(2,257): x.born(pid)
    yield record(s,'255-unrelated-born', 'OK',x,selected)
    for pid in range(2,257): x.died(pid)
    yield record(s,'255-unrelated-exited','OK',x,selected)
    yield record(s,'257th-unique-birth',x.born(257),x,selected)
    yield record(s,'selected-lookup-after-cap','lookup',x,selected)
    x=Ledger(); s='unrelated-pid-reuse'; selected=1
    x.born(1); x.born(2);x.died(2)
    yield record(s,'two-born-one-dead','OK',x,selected)
    yield record(s,'unrelated-pid-2-reborn',x.born(2),x,selected)
    yield record(s,'selected-lookup-after-reuse','lookup',x,selected)
    x=Ledger();s='unrelated-preemption';selected=999
    for pid in range(1,257): x.born(pid)
    yield record(s,'256-unrelated-born','OK',x,selected)
    yield record(s,'selected-257th-birth',x.born(selected),x,selected)
    x=Ledger(); s='all-exited-still-full';selected=999
    for pid in range(1,257):x.born(pid)
    for pid in range(1,257):x.died(pid)
    yield record(s,'all-256-exited','OK',x,selected)
    yield record(s,'new-selected-birth',x.born(selected),x,selected)

def encoded():
    return ''.join('|'.join(map(str,r))+'\n' for r in scenario_rows()).encode()

class Negative(unittest.TestCase):
    def test_selected_process_loses_lookup_after_irrelevant_churn(self):
        r=list(scenario_rows())
        self.assertEqual(r[2],('selected-survives-churn','255-unrelated-exited','OK',256,1,0,1))
        self.assertEqual(r[3],('selected-survives-churn','257th-unique-birth','Full',256,1,1,0))
    def test_unrelated_pid_reuse_latches_session_loss(self):
        r=list(scenario_rows());self.assertEqual(r[6],('unrelated-pid-reuse','unrelated-pid-2-reborn','ReusedPid',2,1,1,0))
    def test_selected_new_process_not_recorded_after_irrelevant_births(self):
        r=list(scenario_rows());self.assertEqual(r[9],('unrelated-preemption','selected-257th-birth','Full',256,256,1,0))
    def test_exited_slots_still_consume_capacity(self):
        r=list(scenario_rows());self.assertEqual(r[11],('all-exited-still-full','new-selected-birth','Full',256,0,1,0))
    def test_records_stable(self):
        self.assertEqual(len(list(scenario_rows())),12)
        self.assertEqual(sum(r[5] for r in scenario_rows()),6)

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Negative))
    print('R91_RECORDS='+str(len(list(scenario_rows()))))
    print('R91_SHA256='+hashlib.sha256(encoded()).hexdigest())
    if not result.wasSuccessful():raise SystemExit(1)
