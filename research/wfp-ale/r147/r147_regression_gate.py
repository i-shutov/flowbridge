#!/usr/bin/env python3
"""Run the pinned, offline R143/R144/R147 regression block in a local snapshot.

No Git write, network, WFP, driver, service or runner configuration operations.
The output directory must not exist. PASS means OFFLINE_QA_PASS only.
The caller trusts this runner; its recorded hash is not self-authentication.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

BASE_SHA = 'ce046f20289da250c7eccde7410e5d216219b1ff'
MAIN_SHA = '5b5afc2feeda2195f302380e615ba003d4906e09'
BRANCH = 'research/windows-wfp-ale-attribution-20261107'
PINS = {'research/wfp-ale/r141/R141_DESIGN_ONLY_DESCRIPTORS.json': 'b9c1e5f2c7ffed691d613fa2f8927d7fd8582fc6', 'research/wfp-ale/r143/r143_policy_compiler.py': 'a9948ffe5ca9bce253541b078afdb44f0e3931a3', 'research/wfp-ale/r143/test_r143.py': 'a8405f5a53c2d867745881c3499a228a0a305165', 'research/wfp-ale/r143/r143_independent.mjs': '1a3c9a1aed1e9e7e0a680929a9df094633843588', 'research/wfp-ale/r144/r144_compiled_blueprint_negative.py': '01e20cadf8c5d6d9142155565349dbf251a6364b', 'research/wfp-ale/r144/r144_independent_oracle.mjs': '5becbc90ab6777213168f48236d96514b94db1c4', 'research/wfp-ale/r147/r147_blueprint_verify.py': 'ebc3d807b7b3da6b17c29a6d0ee8b1e730751ae7', 'research/wfp-ale/r147/r147_blackbox.mjs': '1de9246bfeb0258d598096895ebb7aafb84ec937', 'research/wfp-ale/r147/test_r147.py': '2e3bcaa501e01bf541a29cf8b8d305e66f0cbd96'}
MAX_SOURCE = 262144
MATRIX_SHA = '79bb1b4f251e06225fa175601c768b85faffe48c6b8ad8400a249cd105d7a49b'


class GateFailure(ValueError):
    pass


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()


def normalized(raw: bytes, expected: str) -> tuple[bytes, bool]:
    if git_blob(raw) == expected:
        return raw, False
    lf = raw.replace(b'\r\n', b'\n')
    if git_blob(lf) == expected:
        return lf, True
    raise GateFailure('SOURCE_BLOB_MISMATCH')


def snapshot_sources(root: Path, dest: Path) -> list[dict]:
    captured = []
    # Verify every file before copying or executing any of the payloads.
    for relative, expected in PINS.items():
        path = root / relative
        with path.open('rb') as source:
            raw = source.read(MAX_SOURCE + 1)
        if len(raw) > MAX_SOURCE:
            raise GateFailure('SOURCE_TOO_LARGE:' + relative)
        try:
            executed, changed = normalized(raw, expected)
        except GateFailure as exc:
            raise GateFailure('SOURCE_BLOB_MISMATCH:' + relative) from exc
        captured.append((relative, raw, executed, changed))
    inventory = []
    for relative, raw, executed, changed in captured:
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(executed)
        inventory.append({'path': relative, 'raw_git_blob': git_blob(raw),
                          'executed_git_blob': git_blob(executed),
                          'raw_sha256': hashlib.sha256(raw).hexdigest(),
                          'executed_sha256': hashlib.sha256(executed).hexdigest(),
                          'crlf_normalized': changed})
    # Unit tests import the currently executing runner's helper functions.
    own = Path(__file__).read_bytes()
    own_target = dest / 'research/wfp-ale/r147/r147_regression_gate.py'
    own_target.parent.mkdir(parents=True, exist_ok=True)
    own_target.write_bytes(own)
    inventory.append({'path': 'research/wfp-ale/r147/r147_regression_gate.py',
                      'executed_git_blob': git_blob(own),
                      'executed_sha256': hashlib.sha256(own).hexdigest(),
                      'attestation': 'RUNNER_SELF_HASH_NOT_INDEPENDENT_AUTHENTICATION'})
    return inventory


def exact_json(value, expected) -> bool:
    return json.dumps(value, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False)


def parse_unittest(stderr: str, count: int) -> None:
    if not re.search(r'\bRan ' + str(count) + r' tests?\b', stderr) or not stderr.rstrip().endswith('OK'):
        raise GateFailure('INCOMPLETE_UNITTEST_REPORT')


def commands(node: str) -> list[tuple[str, list[str], int | None]]:
    root = 'research/wfp-ale/'
    python = sys.executable
    return [
        ('r143_normal', [python, '-B', root + 'r143/test_r143.py'], 74),
        ('r143_optimized', [python, '-O', '-B', root + 'r143/test_r143.py'], 74),
        ('r144_normal', [python, '-B', root + 'r144/r144_compiled_blueprint_negative.py'], None),
        ('r144_optimized', [python, '-O', '-B', root + 'r144/r144_compiled_blueprint_negative.py'], None),
        ('r143_node', [node, root + 'r143/r143_independent.mjs'], None),
        ('r144_node', [node, root + 'r144/r144_independent_oracle.mjs'], None),
        ('r147_normal', [python, '-B', root + 'r147/test_r147.py'], UNIT_COUNT),
        ('r147_optimized', [python, '-O', '-B', root + 'r147/test_r147.py'], UNIT_COUNT),
        ('r147_blackbox', [node, root + 'r147/r147_blackbox.mjs'], None),
    ]


UNIT_COUNT = 36
GROUPS = {
    'baseline': ('r143_normal', 'r143_optimized', 'r144_normal', 'r144_optimized', 'r143_node', 'r144_node'),
    'boundary': ('r147_normal',),
    'boundary_optimized': ('r147_optimized',),
    'blackbox': ('r147_blackbox',),
}


def checkpoint(output: Path, result: dict) -> None:
    temporary = output / 'R147_EVIDENCE.json.tmp'
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    temporary.replace(output / 'R147_EVIDENCE.json')


def run_gate(root: Path, output: Path, preflight_only: bool = False, group: str = 'all') -> dict:
    output.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'OFFLINE_REGRESSION_EVIDENCE', 'base_sha': BASE_SHA,
              'main_sha_observed_at_development': MAIN_SHA, 'branch': BRANCH,
              'python': sys.version, 'platform': sys.platform,
              'group': group, 'status': 'RUNNING_NOT_ACCEPTED', 'native_wfp_executed': False,
              'release_accepted': False, 'no_direct_proved': False, 'commands': []}
    checkpoint(output, result)
    try:
        with tempfile.TemporaryDirectory(prefix='flowbridge-r147-') as tmp:
            snapshot = Path(tmp)
            result['sources'] = snapshot_sources(root, snapshot)
            checkpoint(output, result)
            if preflight_only:
                result['status'] = 'PREFLIGHT_ONLY_NOT_TESTED'
                return result
            node = shutil.which('node')
            if node is None:
                raise GateFailure('NODE_NOT_FOUND')
            env = os.environ.copy()
            env.update({'PYTHON': sys.executable, 'PYTHONDONTWRITEBYTECODE': '1',
                        'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8'})
            outputs = {}
            plan = commands(node)
            if group != 'all':
                if group not in GROUPS:
                    raise GateFailure('UNKNOWN_GROUP')
                plan = [entry for entry in plan if entry[0] in GROUPS[group]]
            for label, argv, expected_count in plan:
                try:
                    completed = subprocess.run(argv, cwd=snapshot, env=env, shell=False,
                                               capture_output=True, timeout=120)
                except subprocess.TimeoutExpired as exc:
                    for channel in ('stdout', 'stderr'):
                        raw = getattr(exc, channel) or b''
                        (output / (label + '.' + channel)).write_bytes(raw)
                    result['commands'].append({'name': label, 'exit_code': None, 'timed_out': True})
                    checkpoint(output, result)
                    raise GateFailure('CHILD_TIMEOUT:' + label) from exc
                for channel in ('stdout', 'stderr'):
                    (output / (label + '.' + channel)).write_bytes(getattr(completed, channel))
                result['commands'].append({'name': label, 'exit_code': completed.returncode,
                    'stdout_sha256': hashlib.sha256(completed.stdout).hexdigest(),
                    'stderr_sha256': hashlib.sha256(completed.stderr).hexdigest()})
                checkpoint(output, result)
                if completed.returncode != 0:
                    raise GateFailure('CHILD_FAILED:' + label)
                text = completed.stdout.decode('utf-8').replace('\r\n', '\n')
                error = completed.stderr.decode('utf-8').replace('\r\n', '\n')
                outputs[label] = text
                if expected_count is not None:
                    parse_unittest(error, expected_count)
            if group == 'all':
                result['blackbox'] = validate_outputs(outputs)
                result['status'] = 'OFFLINE_QA_PASS'
            else:
                result['status'] = 'OFFLINE_GROUP_PASS_NOT_AGGREGATED'
    except (GateFailure, OSError, ValueError, subprocess.SubprocessError) as exc:
        result['status'] = 'FAILED'
        result['error'] = type(exc).__name__ + ':' + str(exc)
    finally:
        checkpoint(output, result)
    return result


def validate_outputs(outputs: dict) -> list[dict]:
    expected_names = {entry[0] for entry in commands('node')}
    if set(outputs) != expected_names:
        raise GateFailure('MISSING_OR_EXTRA_COMMANDS')
    if not (outputs['r144_normal'] == outputs['r144_optimized'] == outputs['r144_node']):
        raise GateFailure('R144_INDEPENDENT_MISMATCH')
    matrix = json.loads(outputs['r143_node'])
    if (type(matrix.get('states')) is not int or matrix['states'] != 2048
            or type(matrix.get('native_acceptances')) is not int or matrix['native_acceptances'] != 0
            or matrix.get('release_accepted') is not False):
        raise GateFailure('R143_MATRIX_MISMATCH')
    blackbox = [json.loads(line) for line in outputs['r147_blackbox'].splitlines()]
    if len(blackbox) != 2:
        raise GateFailure('R147_MISSING_MODE')
    for mode, row in zip((False, True), blackbox, strict=True):
        if not exact_json(row, {'optimized': mode, 'states': 2125, 'accepted': 3, 'rejected': 2122,
                                'sha256': MATRIX_SHA, 'native_wfp_executed': False, 'release_accepted': False}):
            raise GateFailure('R147_MATRIX_MISMATCH')
    return blackbox


def aggregate_parts(parts: list[Path], output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    result = {'status': 'FAILED', 'kind': 'OFFLINE_REGRESSION_AGGREGATE',
              'base_sha': BASE_SHA, 'branch': BRANCH, 'commands': [],
              'native_wfp_executed': False, 'release_accepted': False, 'no_direct_proved': False}
    try:
        if len(parts) != len(GROUPS):
            raise GateFailure('ALL_FOUR_GROUPS_REQUIRED')
        seen = set()
        outputs = {}
        expected_pins = dict(PINS)
        expected_pins['research/wfp-ale/r147/r147_regression_gate.py'] = git_blob(Path(__file__).read_bytes())
        counts = {name: count for name, _, count in commands('node')}
        for directory in parts:
            evidence_path = directory / 'R147_EVIDENCE.json'
            with evidence_path.open('rb') as file:
                raw = file.read(MAX_SOURCE + 1)
            if len(raw) > MAX_SOURCE:
                raise GateFailure('RECEIPT_TOO_LARGE')
            data = json.loads(raw)
            group = data.get('group')
            if group not in GROUPS or group in seen:
                raise GateFailure('DUPLICATE_OR_UNKNOWN_GROUP')
            seen.add(group)
            if (data.get('status') != 'OFFLINE_GROUP_PASS_NOT_AGGREGATED'
                    or data.get('base_sha') != BASE_SHA or data.get('branch') != BRANCH
                    or any(data.get(key) is not False for key in ('native_wfp_executed', 'release_accepted', 'no_direct_proved'))):
                raise GateFailure('PART_NOT_ACCEPTABLE')
            sources = data.get('sources', [])
            source_pins = {item['path']: item['executed_git_blob'] for item in sources}
            if len(sources) != len(expected_pins) or source_pins != expected_pins:
                raise GateFailure('PART_EXECUTION_BYTES_CHANGED')
            runs = data.get('commands', [])
            if [entry.get('name') for entry in runs] != list(GROUPS[group]):
                raise GateFailure('PART_COMMAND_SET_CHANGED')
            for entry in runs:
                name = entry['name']
                if type(entry.get('exit_code')) is not int or entry['exit_code'] != 0:
                    raise GateFailure('PART_COMMAND_FAILED')
                text = {}
                for channel in ('stdout', 'stderr'):
                    with (directory / (name + '.' + channel)).open('rb') as file:
                        content = file.read(8 * 1024 * 1024 + 1)
                    if len(content) > 8 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != entry[channel + '_sha256']:
                        raise GateFailure('PART_LOG_CHANGED')
                    text[channel] = content.decode('utf-8').replace('\r\n', '\n')
                if counts[name] is not None:
                    parse_unittest(text['stderr'], counts[name])
                outputs[name] = text['stdout']
                result['commands'].append(entry)
        result['blackbox'] = validate_outputs(outputs)
        result['groups'] = sorted(seen)
        result['status'] = 'OFFLINE_QA_PASS'
    except (GateFailure, OSError, ValueError, KeyError, TypeError) as exc:
        result['error'] = type(exc).__name__ + ':' + str(exc)
    finally:
        checkpoint(output, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--group', choices=('all', *GROUPS), default='all')
    parser.add_argument('--aggregate', nargs=4, type=Path, metavar='PART')
    args = parser.parse_args()
    try:
        if args.aggregate:
            result = aggregate_parts(args.aggregate, args.output.resolve())
        else:
            result = run_gate(args.root.resolve(), args.output.resolve(), args.preflight_only, args.group)
    except OSError as exc:
        print(json.dumps({'status': 'FAILED', 'error': type(exc).__name__, 'release_accepted': False}))
        return 2
    print(json.dumps({'status': result['status'], 'commands': len(result['commands']),
                      'evidence': str(args.output / 'R147_EVIDENCE.json'),
                      'native_wfp_executed': False, 'release_accepted': False}, sort_keys=True))
    return 0 if result['status'] in ('OFFLINE_QA_PASS', 'OFFLINE_GROUP_PASS_NOT_AGGREGATED', 'PREFLIGHT_ONLY_NOT_TESTED') else 2


if __name__ == '__main__':
    raise SystemExit(main())
