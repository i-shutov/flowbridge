#!/usr/bin/env python3
"""Source-contract + bounded negative tests; no Windows API or network I/O."""
from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / 'kernel-r19' / 'policy_windows.rs'
PROBE = ROOT / 'r190' / 'main.rs'

def contract(policy: str, probe: str) -> dict[str, bool]:
    return {
        'r19_dynamic_session': bool(re.search(r'session\.flags\s*=\s*FWPM_SESSION_FLAG_DYNAMIC\s*;', policy)),
        'r19_sublayer_add': 'FwpmSubLayerAdd0(' in policy,
        'r19_callout_add': 'FwpmCalloutAdd0(' in policy,
        'r19_filter_add': 'FwpmFilterAdd0(' in policy,
        'r190_sublayer_gate': 'FwpmSubLayerGetByKey0(' in probe and '"sublayer_get_by_key"' in probe,
        'r190_callout_gate': 'FwpmCalloutGetByKey0(' in probe and '"callout_get_by_key"' in probe,
        'r190_filter_gate': 'FwpmFilterGetByKey0(' in probe and '"filter_get_by_key"' in probe,
        'r190_registration_gate': 'FWPM_CALLOUT_FLAG_REGISTERED' in probe,
        'r190_readonly': 'FWPM_TXN_READ_ONLY' in probe,
        'r190_no_bfe_add': not any(n+'(' in probe for n in ('FwpmSubLayerAdd0', 'FwpmCalloutAdd0', 'FwpmFilterAdd0')),
    }

def eligible(*, sublayer: bool, callouts: int, filters: int, registered: int) -> str:
    if not sublayer or callouts != 4 or filters != 4 or registered != 4:
        return 'NO_ATTESTATION'
    return 'STRUCTURE_ONLY_NOT_KERNEL_PROOF'

def run(policy: str, probe: str) -> dict:
    checks = contract(policy, probe)
    checks.update({
        'mutation_dynamic_detected': not contract(policy.replace('session.flags=FWPM_SESSION_FLAG_DYNAMIC', 'session.flags=0'), probe)['r19_dynamic_session'],
        'mutation_filter_detected': not contract(policy, probe.replace('FwpmFilterGetByKey0', 'MUTATED_FILTER_GET'))['r190_filter_gate'],
        'clean_no_objects_no_attestation': eligible(sublayer=False, callouts=0, filters=0, registered=0) == 'NO_ATTESTATION',
        'expired_dynamic_session_no_attestation': eligible(sublayer=False, callouts=0, filters=0, registered=0) == 'NO_ATTESTATION',
        'unregistered_callout_no_attestation': eligible(sublayer=True, callouts=4, filters=4, registered=3) == 'NO_ATTESTATION',
        'all_visible_is_only_structure': eligible(sublayer=True, callouts=4, filters=4, registered=4) == 'STRUCTURE_ONLY_NOT_KERNEL_PROOF',
    })
    return {'checks': checks, 'passed': sum(checks.values()), 'total': len(checks), 'scope': 'source-level / modeled, not native'}

if __name__ == '__main__':
    if not POLICY.is_file() or not PROBE.is_file():
        sys.exit('NO_SOURCE: requires complete research/wfp-ale checkout')
    result = run(POLICY.read_text(encoding='utf-8'), PROBE.read_text(encoding='utf-8'))
    print(json.dumps(result, sort_keys=True))
    sys.exit(0 if result['passed'] == result['total'] else 1)
