#!/usr/bin/env python3
"""Verify that real group receipts cannot be accepted after isolated corruption.

Usage: python -B r147_receipt_mutations.py /path/to/evidence/groups
All alterations occur in temporary copies. Original evidence is read-only.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gate', HERE / 'r147_regression_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
LABELS = ('valid', 'missing_group', 'duplicate_group', 'wrong_branch', 'wrong_base',
          'unfinished', 'false_as_zero', 'exit_as_false', 'source_pin', 'missing_command',
          'log_tamper', 'rehash_wrong_summary', 'rehash_missing_tests', 'repeated_mode')


def main():
    original = Path(sys.argv[1]).resolve()
    rows = []
    for label in LABELS:
        with tempfile.TemporaryDirectory(prefix='fb-r147-receipts-') as tmp:
            temp = Path(tmp)
            for name in gate.GROUPS:
                shutil.copytree(original / name, temp / name)
            parts = [temp / name for name in gate.GROUPS]
            directory = temp / ('blackbox' if label in ('rehash_wrong_summary', 'repeated_mode')
                                else 'boundary' if label == 'rehash_missing_tests' else 'baseline')
            receipt_path = directory / 'R147_EVIDENCE.json'
            receipt = json.loads(receipt_path.read_bytes())
            if label == 'missing_group': parts.pop()
            elif label == 'duplicate_group': parts[1] = parts[0]
            elif label == 'wrong_branch': receipt['branch'] = 'main'
            elif label == 'wrong_base': receipt['base_sha'] = '0' * 40
            elif label == 'unfinished': receipt['status'] = 'RUNNING_NOT_ACCEPTED'
            elif label == 'false_as_zero': receipt['release_accepted'] = 0
            elif label == 'exit_as_false': receipt['commands'][0]['exit_code'] = False
            elif label == 'source_pin': receipt['sources'][0]['executed_git_blob'] = '0' * 40
            elif label == 'missing_command': receipt['commands'].pop()
            elif label in ('log_tamper', 'rehash_missing_tests', 'rehash_wrong_summary', 'repeated_mode'):
                entry = receipt['commands'][0]
                channel = 'stderr' if label == 'rehash_missing_tests' else 'stdout'
                log = directory / (entry['name'] + '.' + channel)
                raw = log.read_bytes()
                if label == 'log_tamper': raw += b'CORRUPT'
                elif label == 'rehash_missing_tests': raw = raw.replace(b'Ran 36 tests', b'Ran 0 tests')
                else:
                    records = [json.loads(line) for line in raw.splitlines()]
                    if label == 'rehash_wrong_summary': records[0]['accepted'] = 2125
                    else: records[1]['optimized'] = False
                    raw = ('\n'.join(json.dumps(x) for x in records) + '\n').encode()
                log.write_bytes(raw)
                if label != 'log_tamper': entry[channel + '_sha256'] = hashlib.sha256(raw).hexdigest()
            receipt_path.write_text(json.dumps(receipt), encoding='utf-8')
            result = gate.aggregate_parts(parts, temp / 'result')
            accepted = result['status'] == 'OFFLINE_QA_PASS'
            if accepted != (label == 'valid'):
                raise RuntimeError('aggregate unexpectedly accepted/rejected: ' + label)
            rows.append(f'{label}|{int(accepted)}\n')
    print(json.dumps({'cases': len(rows), 'accepted': 1, 'rejected': len(rows) - 1,
                      'sha256': hashlib.sha256(''.join(rows).encode()).hexdigest(),
                      'native_wfp_executed': False, 'release_accepted': False}, sort_keys=True))


if __name__ == '__main__':
    main()
