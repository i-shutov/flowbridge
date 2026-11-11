"""R111 independent Python negative matrix: synthetic BFE flags, NOT Windows proof."""
from hashlib import sha256
from itertools import product
import json
OWNER = (0,64,32,96,16,1,8,128)
OTHER = (0,64,32,96,16,1,128)
h = sha256()
a = dict(cases=0,old_candidates=0,corrected_candidates=0,false_old_candidates=0,
         disabled_foreign_active_owner=0,bad_owned_flags=0,absent_owned=0)
for rule,visible,o,f,weight in product(range(4),(0,1),OWNER,OTHER,(-1,0,1)):
    old = ('UNKNOWN_OWNED_NOT_VISIBLE' if not visible else
           'VISIBLE_ARBITRATION_CANDIDATE' if weight>=0 else 'UNKNOWN_NO_ACTIVE_COMPETITOR')
    new = ('UNKNOWN_OWNED_NOT_VISIBLE' if not visible else
           'UNKNOWN_OWNED_FLAGS' if o & ~64 else
           'UNKNOWN_NO_ACTIVE_COMPETITOR' if f & 32 else
           'VISIBLE_ARBITRATION_CANDIDATE' if weight>=0 else 'UNKNOWN_NO_ACTIVE_COMPETITOR')
    before=old=='VISIBLE_ARBITRATION_CANDIDATE'
    after=new=='VISIBLE_ARBITRATION_CANDIDATE'
    a['cases']+=1;a['old_candidates']+=before;a['corrected_candidates']+=after
    a['false_old_candidates']+=before and not after
    a['disabled_foreign_active_owner']+=bool(visible and not (o & ~64) and (f & 32))
    a['bad_owned_flags']+=bool(visible and (o & ~64))
    a['absent_owned']+=not visible
    h.update(f'{rule}|{visible}|{o}|{f}|{weight}|{old}|{new}\n'.encode())
a['unsafe_permits']=0;a['decision_sha256']=h.hexdigest()
a['native_windows_executed']=False;a['kernel_origin_proof']=False
assert (a['cases'],a['old_candidates'],a['corrected_candidates'],a['false_old_candidates'])==(1344,448,80,368)
print(json.dumps(a,sort_keys=True))
