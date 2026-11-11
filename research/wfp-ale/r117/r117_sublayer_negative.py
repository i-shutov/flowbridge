#!/usr/bin/env python3
"""R117 independent synthetic oracle; no WFP calls and no system writes."""
import hashlib, itertools, json
from pathlib import Path

def verdict(available, owner_count, owned_ok, higher, equal, lower, visible):
    if not available or owner_count != 1 or not owned_ok:
        return 2
    if visible > 16384 or higher+equal+lower != visible-1:
        return 2
    return 3 if higher or equal or lower else 4

def outcomes():
    for x in itertools.product((False, True),(0,1,2),(False,True),
                               (0,1,2,4),(0,1,3),(0,1,2,4),(0,1,3,7,25)):
        yield verdict(*x)

def run():
    values=list(outcomes())
    assert len(values)==2880
    assert set(values)=={2,3,4}
    assert verdict(True,1,True,0,0,0,1)==4
    assert verdict(True,1,True,1,0,0,2)==3
    assert verdict(True,1,True,0,1,0,2)==3
    assert verdict(True,1,True,0,0,1,2)==3  # lower sublayer can veto / override soft permit
    assert verdict(True,0,True,0,0,0,0)==2
    assert verdict(True,1,True,1,0,0,1)==2
    assert verdict(True,1,False,0,0,0,1)==2
    src=Path(__file__).with_name('r117_readonly_sublayer_peers.rs').read_text()
    for api in ('FwpmSubLayerCreateEnumHandle0','FwpmSubLayerEnum0',
                'FwpmSubLayerDestroyEnumHandle0','FwpmFreeMemory0'):
        assert api in src
    for forbidden in ('FwpmSubLayerAdd0','FwpmFilterAdd0','FwpsCalloutRegister',
                      'FwpmTransactionBegin0','std::net::','Command::new'):
        assert forbidden not in src
    buf=''.join(f'{i},{v}\n' for i,v in enumerate(values)).encode('ascii')
    d={'cases':len(values),'exit_2':values.count(2),'exit_3':values.count(3),
       'exit_4':values.count(4),'matrix_sha256':hashlib.sha256(buf).hexdigest()}
    print(json.dumps(d,sort_keys=True))
if __name__=='__main__':run()
