#!/usr/bin/env python3
"""R204: R199 BFE engine-code/exit consistency; no kernel proof."""
import argparse
import json
import pathlib
import sys

def accept(bfe, exit_code):
    if type(exit_code) is not int or exit_code not in (0, 3):
        return False
    if type(bfe) is not dict or bfe.get('kernel_proof') is not False or bfe.get('atomic') is not False:
        return False
    code = bfe.get('engine_api_code')
    if type(code) is not int or not 0 <= code <= 0xffffffff:
        return False
    if bfe.get('state') == 'MANAGEMENT_READBACK_NOT_PROOF':
        return code == 0 and exit_code == 0
    if bfe.get('state') == 'UNKNOWN':
        return exit_code == 3
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--evidence-dir', type=pathlib.Path)
    a = ap.parse_args()
    if a.self_test:
        cases = [
            ('MANAGEMENT_READBACK_NOT_PROOF', 0, 0, True),
            ('UNKNOWN', 5, 3, True),
            ('UNKNOWN', 0, 3, True),
            ('MANAGEMENT_READBACK_NOT_PROOF', 5, 0, False),
            ('MANAGEMENT_READBACK_NOT_PROOF', None, 0, False),
            ('MANAGEMENT_READBACK_NOT_PROOF', 0, 3, False),
            ('UNKNOWN', 5, 0, False),
            ('UNKNOWN', -1, 3, False),
            ('UNKNOWN', 0x100000000, 3, False),
            ('UNKNOWN', True, 3, False),
        ]
        for state, code, exit_code, expected in cases:
            bfe = dict(state=state, kernel_proof=False, atomic=False)
            if code is not None:
                bfe['engine_api_code'] = code
            assert accept(bfe, exit_code) == expected, (state, code, exit_code)
        print('R204-PY 10/10 PASS: semantic gate only, not Windows runtime')
        return 0
    if a.evidence_dir is None:
        ap.error('specify --self-test or --evidence-dir')
    e = json.loads((a.evidence_dir / 'evidence.json').read_text(encoding='utf-8-sig'))
    if e.get('bfe_requested') is not True:
        print('NOT_APPLICABLE_BFE_NOT_REQUESTED')
        return 3
    item = e['results']['r199-readback']
    if item['stdout'] != 'r199-readback.stdout.txt':
        raise ValueError('unexpected BFE stdout path')
    bfe = json.loads((a.evidence_dir / item['stdout']).read_text(encoding='utf-8-sig'))
    okay = accept(bfe, item['exit_code'])
    print('R204_BFE_MANAGEMENT_CONSISTENCY_ACCEPTED_NOT_KERNEL_PROOF' if okay else 'REJECTED_NO_GO')
    return 0 if okay else 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, TypeError, ValueError, KeyError, AssertionError) as exc:
        print('REJECTED_NO_GO: ' + str(exc), file=sys.stderr)
        sys.exit(1)
