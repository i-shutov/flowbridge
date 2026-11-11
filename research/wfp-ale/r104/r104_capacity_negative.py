#!/usr/bin/env python3
"""Offline Python negative model, not a native WFP or kernel test."""
from hashlib import sha256
CAP=256
N=(0,1,2,253,254,255,256,257)
class Tracker:
    def __init__(self):
        self.owners={}
        self.lost=False
    def born(self,pid):
        if self.lost:return False
        if pid in self.owners:
            self.owners[pid]=False;self.lost=True;return False
        if len(self.owners)>=CAP:
            self.lost=True;return False
        self.owners[pid]=True;return True
    def died(self,pid):
        if pid in self.owners:self.owners[pid]=False
    def observe(self,pid):
        return ("LOST" if self.lost else "UNKNOWN" if pid not in self.owners
                else "OK" if self.owners[pid] else "DEAD")
def evaluate(family,scenario,n):
    tr=Tracker(); selected=900000
    if scenario=="target_first": assert tr.born(selected)
    for index in range(n):
        pid=index+1;tr.born(pid)
        if scenario=="dead_churn":tr.died(pid)
    if scenario!="target_first":tr.born(selected)
    state=tr.observe(selected)
    assert state==("OK" if n<=255 else "LOST")
    return f"{family}|{scenario}|{n}|{state}|{len(tr.owners)}|{int(tr.lost)}"
def run():
    rows=[evaluate(f,s,n) for f in (4,6)
          for s in ("target_last","target_first","dead_churn") for n in N]
    for family in (4,6):
        tr=Tracker();assert tr.born(42);tr.died(42)
        assert not tr.born(42) and tr.observe(42)=="LOST"
        rows.append(f"{family}|pid_reuse|1|LOST|1|1")
        tr=Tracker(); assert tr.born(900000)
        for i in range(1,256):assert tr.born(i)
        assert tr.observe(900000)=="OK"
        assert not tr.born(256) and tr.observe(900000)=="LOST"
        rows.append(f"{family}|257th_unrelated|256|LOST|256|1")
    assert len(rows)==52 and sum(x.split("|")[3]=="LOST" for x in rows)==16
    digest=sha256(("\n".join(rows)+"\n").encode()).hexdigest()
    assert digest=="5974b31d3a79c93b6dc82b7e3ef459844fa01c54f39b6edbd34fd6077230f356"
    print(f"R104 PYTHON PASS: {len(rows)} cases, 16 LOST; {digest}")
if __name__=="__main__":run()
