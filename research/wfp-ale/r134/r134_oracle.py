#!/usr/bin/env python3
"""Independent offline observation gate. Bit 7 is NOT identity authority."""
import hashlib,json

def exit_for(mask):
    checks=[bool(mask&(1<<i)) for i in range(7)]
    return 0 if all(checks) else 3

def matrix():return ''.join(f'{m:03}:{exit_for(m)}\n' for m in range(256))
def result():
    rows=matrix()
    return {'states':256,'consistent':sum(exit_for(i)==0 for i in range(256)),
            'sha256':hashlib.sha256(rows.encode('ascii')).hexdigest()}
if __name__=='__main__':print(json.dumps(result(),sort_keys=True))
