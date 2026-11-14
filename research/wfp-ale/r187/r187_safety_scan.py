"""Independent read-only surface gate; does not compile or execute Rust/Windows."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'src' / 'main.rs'
ALLOWED = {
    'FwpmEngineOpen0', 'FwpmEngineClose0', 'FwpmFreeMemory0',
    'FwpmTransactionBegin0', 'FwpmTransactionCommit0', 'FwpmTransactionAbort0',
    'FwpmSessionCreateEnumHandle0', 'FwpmSessionEnum0', 'FwpmSessionDestroyEnumHandle0',
    'FwpmSubLayerGetByKey0', 'FwpmFilterGetByKey0', 'FwpmCalloutGetByKey0',
}
REQUIRED = ALLOWED - {'FwpmTransactionAbort0'}
BANNED_PREFIX = ('Fwps', 'DeviceIoControl', 'WSAIoctl', 'CreateService',
                 'socket', 'connect', 'bind', 'listen', 'send', 'recv')


def audit(source):
    calls = set(re.findall(r'\b(Fwpm\w+|Fwps\w+|DeviceIoControl|WSAIoctl|CreateService|socket|connect|bind|listen|send|recv)\s*\(', source))
    violations = sorted(calls - ALLOWED)
    missing = sorted(REQUIRED - calls)
    guards = {
        'read_only_transaction': bool(re.search(r'FwpmTransactionBegin0\s*\(\s*engine\.0\s*,\s*FWPM_TXN_READ_ONLY\s*\)', source)),
        'no_dynamic_session': 'FWPM_SESSION_FLAG_DYNAMIC' not in source,
        'no_kernel_claim': 'kernel_identity\\":\\"UNKNOWN' in source or 'kernel_identity\\":\\"UNKNOWN' in source.replace('\\\\','\\'),
        'no_enforcement_claim': 'enforcement\\":\\"UNKNOWN' in source or 'enforcement\\":\\"UNKNOWN' in source.replace('\\\\','\\'),
        'no_continuity_claim': 'continuity\\":\\"UNKNOWN' in source or 'continuity\\":\\"UNKNOWN' in source.replace('\\\\','\\'),
        'no_go_token': not re.search(r'\b(PACKETBOUND_PASS|LEAK_FREE|G2_PASS)\b', source),
    }
    return {'safe': not violations and not missing and all(guards.values()),
            'calls': sorted(calls), 'violations': violations, 'missing': missing, 'guards': guards}


if __name__ == '__main__':
    print(json.dumps(audit(SOURCE.read_text()), sort_keys=True))
