"""Independent offline truth-table oracle. Does not import any production/model module."""
from itertools import product
from collections import Counter
def oracle(x):
    fam,proto,ticket,claim,wfp,ssh,peer,peer_ticket,child,peer_child,gen,peer_gen,remote=x
    if proto!=6 or not ticket or not (claim and wfp and ssh):
        return "REJECT"
    if peer!="PIPE" or peer_ticket!=ticket or child==0 or gen==0 or child!=peer_child or gen!=peer_gen:
        return "REJECT"
    return "CONDITIONAL_RELEASE" if remote else "LOCAL_PEER_ONLY"
def bad(x):
    return x[6] in ("SOCKS","PID") and x[3] and x[4] and x[5] and x[12]
counts=Counter()
mutant_false_accepts=0
for x in product((4,6),(6,17),(0,31,32),(False,True),(False,True),(False,True),
                 ("SOCKS","PID","PIPE"),(31,32),(23,24),(23,24),(9,10),(9,10),(False,True)):
    y=oracle(x)
    counts[y]+=1
    if bad(x) and y=="REJECT":mutant_false_accepts+=1
assert sum(counts.values())==18432
assert counts==Counter({"REJECT":18400,"LOCAL_PEER_ONLY":16,"CONDITIONAL_RELEASE":16})
assert mutant_false_accepts==768
a=("127.0.0.1",1080,bytes([5,0]),bytes([5,0,0,1]),"real-ssh")
b=("127.0.0.1",1080,bytes([5,0]),bytes([5,0,0,1]),"substitute")
assert a[:-1]==b[:-1] and a[-1]!=b[-1]
print("R34 oracle PASS",dict(counts),"unsafe false accepts",mutant_false_accepts)
