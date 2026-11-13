#!/usr/bin/env python3
"""Independent Python finite trace oracle for unreachable R19 Witness writer."""
from hashlib import sha256
from itertools import product
import json
EVENTS = ('birth','exit','reuse','redirect4','redirect6','auth4','auth6','pop')
def trace(seq):
    used, lost = 0, False
    output = []
    for event in seq:
        if event == 'birth' and not lost:
            if used == 256: lost = True
            else: used += 1
        elif event == 'reuse' and used:
            lost = True
        elif event == 'pop':
            output.append('NOT_READY' if lost else 'EMPTY')
        elif event not in EVENTS:
            raise ValueError(event)
    return ','.join(output)+'|'+str(used)+'|'+str(int(lost))+'|0'
def matrix():
    h = sha256(); total = reads = 0
    for n in range(6):
        for seq in product(EVENTS,repeat=n):
            result = trace(seq)
            if 'SUCCESS' in result: raise RuntimeError('UNREACHABLE_PRODUCER')
            h.update((','.join(seq)+'|'+result+'\n').encode())
            total+=1; reads+=seq.count('pop')
    cap=trace(['birth']*257+['pop'])
    if cap!='NOT_READY|256|1|0': raise RuntimeError('CAPACITY_TEST_FAILED')
    return {'traces':total,'pop_events':reads,'witness_success':0,
            'sha256':h.hexdigest(),'capacity_trace':cap}
if __name__ == '__main__':
    print(json.dumps(matrix(),sort_keys=True))
