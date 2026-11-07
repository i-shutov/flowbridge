#!/usr/bin/env python3
"""Run the separate Python test harness against deliberate unsafe source edits.

All Winsock/BFE functions are mocked by the tests. No Windows experiment.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'socket_endpoint_r17.py'
MUTATIONS = {
    'foreign_endpoint_allowed': ('if info.endpoint != endpoint:', 'if False:'),
    'endpoint_rebind_ignored': ('if decode_endpoint(api.query(sock.fileno(), QUERY_ENDPOINT, 8)) != endpoint:',
                              'if False:'),
    'false_g2_admission': ("'g2_pass': False, 'system_no_direct_proved': False", "'g2_pass': True, 'system_no_direct_proved': False"),
    'ioctl_error_relabelled_absent': ("else 'query_error'", "else 'absent'"),
    'bfe_allocation_not_freed': ('self.free(C.byref(raw))', 'pass  # unsafe mutant'),
    'mutating_ioctl_permitted': ('if code not in (QUERY_ENDPOINT, QUERY_RECORDS, QUERY_CONTEXT) or not 0 < size <= CAP:',
                               'if not 0 < size <= CAP:'),
}


def execute(source):
    with tempfile.TemporaryDirectory(prefix='r17-mutant-') as temp:
        directory = Path(temp)
        (directory / SOURCE.name).write_text(source)
        for name in ('test_socket_endpoint_r17.py', 'socket_endpoint_r17.rs'):
            (directory / name).write_bytes((ROOT / name).read_bytes())
        return subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(directory),
                               '-p', 'test_socket_endpoint_r17.py'],
                              capture_output=True, text=True, timeout=20).returncode


def main():
    source = SOURCE.read_text()
    if execute(source):
        raise RuntimeError('baseline_failed')
    results = {}
    for name, (old, new) in MUTATIONS.items():
        if source.count(old) != 1:
            raise RuntimeError('mutation_anchor_ambiguous')
        results[name] = execute(source.replace(old, new)) != 0
    output = {
        'baseline_passed': True,
        'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'mutations_detected': sum(results.values()), 'mutations_total': len(results),
        'results': results, 'native_windows_called': False, 'g2_pass': False,
        'independent_human_review': False,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if all(results.values()) else 1

if __name__ == '__main__': sys.exit(main())
