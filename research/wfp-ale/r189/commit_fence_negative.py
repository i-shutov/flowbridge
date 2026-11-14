#!/usr/bin/env python3
"""R189: BFE COMMIT+readback is not a documented per-flow ALE reauthorization fence.
Offline, synthetic adverse schedules only: NOT observed Windows traffic.
Official: https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
Official: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactioncommit0
"""
from itertools import product
from hashlib import sha256
import json
def run():
    counts=dict(rows=0,naive_green=0,stale_or_unknown=0,unsafe_certificate=0)
    matrix=sha256()
    for fam,proto,scope,grant,direction,queued,phase,loss in product(
      (4,6),('tcp','udp'),('selected','sibling'),(0,1),('out','in'),(0,1),
      ('not_detected','detected_idle','reauth_blocked'),('stable','bfe_lost','ssh_lost')):
        targeted=int(proto=='tcp' and scope=='selected' and grant==1)
        # COMMIT_OK + FILTERS_PRESENT + READ_TXN_COMMIT_OK same for all phases.
        naive_green=targeted
        stale_or_unknown=int(bool(targeted) and
            (phase!='reauth_blocked' or queued==1 or loss!='stable'))
        no_direct_certificate=0  # No kernel-origin proof or completed per-packet fence.
        counts['rows']+=1
        counts['naive_green']+=naive_green
        counts['stale_or_unknown']+=stale_or_unknown
        counts['unsafe_certificate']+=naive_green*(1-no_direct_certificate)
        matrix.update((','.join(map(str,(fam,proto,scope,grant,direction,queued,
           phase,loss,naive_green,stale_or_unknown,no_direct_certificate)))+'\n').encode())
    if counts!=dict(rows=576,naive_green=72,stale_or_unknown=68,unsafe_certificate=72):
        raise RuntimeError("R189 invariant violation: unsafe continuity certificate")
    return dict(counts=counts,matrix_sha256=matrix.hexdigest(),native_windows=False)
if __name__=='__main__': print(json.dumps(run(),sort_keys=True))
