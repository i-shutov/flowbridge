"""R80 offline negative test; no OS, socket, network or WFP calls."""
from itertools import product
from hashlib import sha256
import json


def decide(h, w, live, barrier, close, bfe, mode):
    if bfe: return 'BFE_NO_PROOF'
    if mode == 'source':
        if not h: return 'HEARTBEAT_JOIN_STALLED'
        if w: return 'WORKER_JOIN_STALLED'
    if mode == 'gated' and live and not barrier: return 'HOLD_NO_BARRIER'
    if not close: return 'CLOSE_UNACKED'
    if live and not barrier: return 'CLOSED_WITH_GAP'
    if mode != 'source' and (not h or w): return 'CLOSED_WORKERS_LIVE'
    return 'CONDITIONAL_ONLY'


rows = []
for ip, h, w, live, barrier, close, loss in product(('v4', 'v6'), (0, 1), (0, 1, 32), (0, 1), (0, 1), (0, 1), ('healthy', 'ssh', 'bfe')):
    bfe = loss == 'bfe'
    a, b, c = [decide(h, w, live, barrier, close, bfe, x) for x in ('source', 'early', 'gated')]
    if h and w and not bfe: assert a == 'WORKER_JOIN_STALLED'
    if close and live and not barrier and not bfe: assert b == 'CLOSED_WITH_GAP' and c == 'HOLD_NO_BARRIER'
    if bfe: assert a == b == c == 'BFE_NO_PROOF'
    rows.append([ip, h, w, live, barrier, close, loss, a, b, c])
assert len(rows) == 288
print(json.dumps({'states': len(rows), 'sha256': sha256(''.join(json.dumps(x, separators=(',', ':'))+'\n' for x in rows).encode()).hexdigest()}, sort_keys=True))
