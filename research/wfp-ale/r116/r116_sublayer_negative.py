#!/usr/bin/env python3
"""R116 off-host negative model. No BFE, no Windows writes or network calls."""
import hashlib
import itertools
import json
from pathlib import Path

KEY = int("1649f02425b34e019ca15ca803010019", 16)
WEIGHT = 0x7000
WEIGHTS = (WEIGHT, 0, WEIGHT - 1, WEIGHT + 1, 0xFFFF)

def cases():
    for api_ok, found, key_ok, flags_zero, provider_null, weight in itertools.product(
        (False, True), (False, True), (False, True), (False, True), (False, True), WEIGHTS
    ):
        yield dict(api_ok=api_ok, found=found, key_ok=key_ok, flags_zero=flags_zero,
                   provider_null=provider_null, weight=weight)

def verdict(c):
    if not c['api_ok'] or not c['found']: return 2
    exact = (c['key_ok'] and c['flags_zero'] and c['provider_null']
             and c['weight'] == WEIGHT)
    return 4 if exact else 2

def matrix():
    return [(idx, verdict(c)) for idx,c in enumerate(cases())]

def canonical():
    return ''.join(f'{i},{v}\n' for i,v in matrix()).encode('ascii')

def test():
    result = matrix()
    assert len(result) == 160, len(result)
    assert sum(v==4 for _,v in result) == 1
    assert sum(v==2 for _,v in result) == 159
    sc = list(cases())
    base = dict(api_ok=True,found=True,key_ok=True,flags_zero=True,provider_null=True,weight=WEIGHT)
    assert verdict(base) == 4
    # The original R103 four-filter snapshot does not query this property;
    # it can yield exit 4 with both descriptors, which remains UNKNOWN.
    assert verdict({**base, 'weight':0}) == 2
    assert verdict({**base, 'flags_zero':False}) == 2
    assert verdict({**base, 'provider_null':False}) == 2
    rust=Path(__file__).with_name('r116_readonly_sublayer_probe.rs').read_text()
    for token in ('FwpmSubLayerGetByKey0', 'FWPM', 'FWPM_SUBLAYER0'):
        if token=='FWPM': continue
        if token=='FWPM_SUBLAYER0':
            assert 'Exact x64 C layouts' in rust
        else: assert token in rust
    for forbidden in ('FwpmFilterAdd0', 'FwpmSubLayerAdd0', 'FwpmFilterDeleteByKey0',
                      'FwpmTransactionBegin0', 'TcpStream', 'Command::new'):
        assert forbidden not in rust
    out=hashlib.sha256(canonical()).hexdigest()
    print(json.dumps(dict(total=len(result),descriptor_only=sum(v==4 for _,v in result),
                          unknown=sum(v==2 for _,v in result),sha256=out),sort_keys=True))
    return out
if __name__=='__main__': test()
