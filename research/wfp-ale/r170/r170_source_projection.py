#!/usr/bin/env python3
"""R170 independent FBR3 compartment-projection negative tests (NO WFP/driver)."""
import json, struct, subprocess
from pathlib import Path
H=Path(__file__).resolve().parent; ROOT=H.parents[2]
PINS={'redirect.rs':'a093f049d162987981a957aac90db1014bc6ff09',
      'policy_windows.rs':'acf60334320d970f58af3349ee75fbaa59826602',
      'lib.rs':'53f5ce6faa0f9f591974287f38ea890cafeb0dd2'}
def gate():
    for name,sha in PINS.items():
        snapshot=ROOT/'snapshot'/name
        repository=ROOT/'research'/'wfp-ale'/'kernel-r19'/('kernel/src/'+name if name!='policy_windows.rs' else name)
        path=snapshot if snapshot.exists() else repository
        got=subprocess.check_output(['git','hash-object',str(path)],text=True).strip()
        if got!=sha:raise RuntimeError('PIN_MISMATCH:'+name)
        if name=='redirect.rs':
            code=path.read_text()
            for family in ['V4','V6']:
                for field in ['ALE_CONNECT_REDIRECT','ALE_AUTH_CONNECT']:
                    if ('FWPS_FIELD_'+field+'_'+family+'_COMPARTMENT_ID') in code:
                        raise RuntimeError('COMPARTMENT_ALREADY_USED')
                if ('FWPS_FIELD_ALE_AUTH_CONNECT_'+family+'_ALE_ORIGINAL_APP_ID') not in code:
                    raise RuntimeError('SOURCE_ANCHOR_LOST')
def wire(family,pid,endpoint,ip):
    b=bytearray(128);b[:8]=b'FBR3\x01\x00\x80\x00';b[8:24]=bytes(range(1,17))
    for at,value in [(24,7),(32,pid),(40,314159),(48,271828),(56,endpoint),(64,19),(96,987654321)]:
        struct.pack_into('<Q',b,at,value)
    b[72]=family;b[73]=6;b[74:76]=(443).to_bytes(2,'big');b[80:96]=ip
    return bytes(b)
def rows():
    result=[]
    for family,ip in [(4,bytes([198,51,100,10])+bytes(12)),(6,bytes.fromhex('20010db8000000000000000000000001'))]:
        for compartment in [0,1,17,4294967295]:
            for endpoint in [8,999,18446744073709551615]:
                for pid in [100,200]:
                    current=wire(family,pid,endpoint,ip)
                    # Explicitly vary ONLY unrepresented hypothetical compartment.
                    legacy_equal=current==wire(family,pid,endpoint,ip)
                    augmented_equal=(current+(1).to_bytes(4,'little'))==(current+compartment.to_bytes(4,'little'))
                    result.append(dict(family=family,pid=pid,endpoint=str(endpoint),
                                       compartment=compartment,legacy_equal=legacy_equal,
                                       augmented_equal=augmented_equal))
    return result
if __name__=='__main__':
    gate();r=rows()
    if len(r)!=48 or any(not x['legacy_equal'] for x in r) or sum(not x['augmented_equal'] for x in r)!=36:
        raise RuntimeError('MODEL_FAILURE')
    print(json.dumps(r,separators=(',',':')))
