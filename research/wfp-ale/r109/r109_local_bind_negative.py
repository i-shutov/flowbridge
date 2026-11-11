#!/usr/bin/env python3
"""R109: offline deterministic synthetic FWPS_CONNECT_REQUEST0-local-address gate.
Source hypothesis: pinned R19 redirect.rs local_supported; no Windows API calls.
"""
import hashlib
import ipaddress
import json

CASES = (
    (4, '0.0.0.0'), (4, '127.0.0.1'), (4, '127.0.0.2'),
    (4, '10.20.30.40'), (4, '192.0.2.7'), (4, '0.0.0.1'),
    (6, '::'), (6, '::1'), (6, '::2'),
    (6, '2001:db8::5'), (6, 'fe80::1'), (6, '::ffff:192.0.2.7'),
)

def sockaddr_storage(family, local):
    b = bytearray(128)
    b[0:2] = (2 if family == 4 else 23).to_bytes(2, 'little')
    ip = ipaddress.ip_address(local)
    assert ip.version == family
    if family == 4:
        b[4:8] = ip.packed
    else:
        b[8:24] = ip.packed
        # flowinfo [4:8], scope [24:28] are deliberately zero for this matrix
    return bytes(b)

def r19_local_supported(raw, family):
    if family == 4:
        return raw[4:8] in (b'\x00'*4, bytes((127,0,0,1)))
    return raw[24:28] == b'\x00'*4 and (
        raw[8:24] == b'\x00'*16 or raw[8:24] == b'\x00'*15 + b'\x01'
    )

def matrix():
    rows = []
    for family, local in CASES:
        data = sockaddr_storage(family, local)
        for port in (443, 8443):
            for lease in (False, True):
                supported = r19_local_supported(data, family)
                # With assumed other preconditions satisfied, classify() either
                # attempts redirect or calls BLOCK for unsupported local bind.
                action = 'TRY_REDIRECT' if lease and supported else ('BLOCK_LOCAL' if lease else 'BLOCK_LEASE')
                rows.append(dict(family=family, local=local, port=port, lease=lease, action=action))
    return rows

def main():
    rows = matrix()
    lines = [json.dumps(r, sort_keys=True, separators=(',', ':'), ensure_ascii=True) for r in rows]
    digest = hashlib.sha256(('\n'.join(lines) + '\n').encode('utf-8')).hexdigest()
    counts = {name:sum(x['action']==name for x in rows) for name in ('TRY_REDIRECT','BLOCK_LOCAL','BLOCK_LEASE')}
    assert len(rows) == 48 and counts == {'TRY_REDIRECT':8,'BLOCK_LOCAL':16,'BLOCK_LEASE':24}, counts
    assert r19_local_supported(sockaddr_storage(4,'127.0.0.1'),4)
    assert not r19_local_supported(sockaddr_storage(4,'127.0.0.2'),4)
    assert not r19_local_supported(sockaddr_storage(6,'2001:db8::5'),6)
    print(json.dumps(dict(test='R109 Python',cases=len(rows),counts=counts,sha256=digest),sort_keys=True))

if __name__ == '__main__':
    main()
