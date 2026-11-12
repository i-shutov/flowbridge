#!/usr/bin/env python3
"""WFP lifecycle *documentation model*, not OS execution or an allow/deny oracle."""
import hashlib
import json
from itertools import product

LIFETIMES=('dynamic', 'static', 'persistent', 'boot_time')
EVENTS=('boot_before_bfe', 'bfe_active', 'owner_exited', 'bfe_runtime_down', 'bfe_restarted', 'reboot_before_bfe')
# Every status except 'missing' means a source-documented possible configuration.
# None proves that traffic was actually blocked or permitted.

def status(lifetime, event, provider_enabled, callout_registered, permit_if_absent):
    if lifetime == 'boot_time':
        phase = 'configured_boot' if event in ('boot_before_bfe','reboot_before_bfe') else 'missing'
    elif lifetime == 'persistent':
        phase = 'stored_only' if event in ('boot_before_bfe','reboot_before_bfe','bfe_runtime_down') else 'configured'
    elif lifetime == 'static':
        phase = 'configured' if event in ('bfe_active','owner_exited') else 'missing'
    elif lifetime == 'dynamic':
        phase = 'configured' if event == 'bfe_active' else 'missing'
    else:
        raise ValueError('unknown lifetime')
    if phase in ('configured','configured_boot') and not provider_enabled:
        phase = 'provider_disabled_or_unverified'
    if phase in ('configured','configured_boot') and not callout_registered:
        phase = 'callout_unregistered_permit_fallback' if permit_if_absent else 'callout_unregistered_block_fallback'
    return phase

def matrix():
    for life, ev, enabled, registered, permit in product(LIFETIMES,EVENTS,(False,True),(False,True),(False,True)):
        yield f'{life}|{ev}|{int(enabled)}|{int(registered)}|{int(permit)}|{status(life,ev,enabled,registered,permit)}|0\n'

def summary():
    rows=list(matrix())
    states={}
    for row in rows:
        value=row.strip().split('|')[5]
        states[value]=states.get(value,0)+1
    return {'scenarios':len(rows),'all_effective_proof_false':True,'statuses':states,
            'sha256':hashlib.sha256(''.join(rows).encode('ascii')).hexdigest()}

if __name__=='__main__':
    print(json.dumps(summary(),sort_keys=True))
