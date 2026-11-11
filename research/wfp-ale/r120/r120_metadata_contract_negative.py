#!/usr/bin/env python3
"""Offline contract witness. This is NOT a real WFP metadata observation.

A frozen R19 auth_check requires four currentMetadataValues bits at ALE_AUTH_CONNECT.
The Microsoft per-layer metadata TABLE lists only two of them for that layer;
redirect GUIDANCE says the other two can be provided there. Both publications
must be retained, not silently reconciled via packet/PID/tuple correlation.
"""
from itertools import product
import hashlib
import json

FIELDS = ("PROCESS_ID", "TRANSPORT_ENDPOINT_HANDLE", "LOCAL_REDIRECT_TARGET_PID", "ORIGINAL_DESTINATION")
TABLE_MASK = 0b0011  # Table at ALE_AUTH_CONNECT v4/v6, among these four fields
REQUIRED = 0b1111

def source_gate(mask, redirected, reauth, lease, ticket, epoch, appid, protocol):
    return (mask & REQUIRED == REQUIRED and redirected == 1 and reauth == 0
            and lease == 1 and ticket == 1 and epoch == 1 and appid == 1
            and protocol == 6)

records = []
for fam, mask, redir, reauth, lease, ticket, epoch, appid, proto in product(
    (4, 6), range(16), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1), (6, 17)):
    result = int(source_gate(mask, redir, reauth, lease, ticket, epoch, appid, proto))
    records.append(f'{fam},{mask},{redir},{reauth},{lease},{ticket},{epoch},{appid},{proto},{result}')
sha = hashlib.sha256(('\n'.join(records)+'\n').encode('ascii')).hexdigest()
accepts = sum(row.endswith(',1') for row in records)
assert len(records) == 4096 and accepts == 2
assert all(not source_gate(TABLE_MASK,1,0,1,1,1,1,6) for _ in (4,6))
assert source_gate(REQUIRED,1,0,1,1,1,1,6)
assert len(FIELDS) == 4
print(json.dumps({'cases':len(records),'synthetic_admissible':accepts,'rejected':len(records)-accepts,
 'table_mask':TABLE_MASK,'required_mask':REQUIRED,'table_admissible':0,
 'matrix_sha256':sha,'source_level_only':True,'native_wfp_observed':False}, sort_keys=True))
