#!/usr/bin/env python3
"""R135: offline ALE action-rights contract model; never invokes Windows APIs."""
import ast
import hashlib
import json
from pathlib import Path
import sys
import unittest

PINNED = {
    'research/wfp-ale/kernel-r19/kernel/src/lib.rs': '0af6d4539673d2894cbaa91af0ea8f3524862a26',
    'research/wfp-ale/kernel-r19/kernel/src/redirect.rs': '9a07e026134d46ef646d39862bd982cc48bbc5f6',
}
ACTIONS = ('BLOCK', 'PERMIT', 'CONTINUE', 'NONE')
PATHS = ('redirect_self', 'redirect_no_write', 'auth_no_write', 'callback_stop')


def git_blob(data):
    return hashlib.sha1(f'blob {len(data)}\0'.encode('ascii') + data).hexdigest()


def assert_pinned_sources(root):
    result = {}
    for path, expected in PINNED.items():
        data = (Path(root) / path).read_bytes()
        actual = git_blob(data)
        if actual != expected:
            raise ValueError(f'source SHA mismatch {path}: {actual} != {expected}')
        result[path] = data.decode('utf-8')
    lib = result['research/wfp-ale/kernel-r19/kernel/src/lib.rs']
    redir = result['research/wfp-ale/kernel-r19/kernel/src/redirect.rs']
    assert 'if !out.is_null() && (*out).rights & k::FWPS_RIGHT_ACTION_WRITE!=0{(*out).actionType=k::FWP_ACTION_CONTINUE;}' in lib
    assert 'if state==k::FWPS_CONNECTION_REDIRECTED_BY_SELF||state==k::FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF{return;}' in redir
    assert 'if incoming_write==0||m.currentMetadataValues&needed!=needed' in redir
    assert 'if (*out).rights & k::FWPS_RIGHT_ACTION_WRITE == 0 {' in redir
    assert 'unsafe fn block(out:*mut k::FWPS_CLASSIFY_OUT0){(*out).actionType=k::FWP_ACTION_BLOCK;' in redir
    assert 'if STOP.load(Ordering::Acquire){if !out.is_null(){(*out).actionType=k::FWP_ACTION_BLOCK;' in lib
    return result


def one(path, has_right, incoming):
    if path in ('redirect_no_write', 'auth_no_write') and has_right:
        return None  # that branch is only selected when ACTION_WRITE is absent
    if path == 'redirect_self':
        # Real entry wrapper initializes CONTINUE when permitted. If no right,
        # redirect::classify blocks before reaching its self-redirect early return.
        written = 'CONTINUE' if has_right else 'BLOCK'
    elif path == 'callback_stop':
        written = 'BLOCK'
    else:
        written = 'BLOCK'
    legal = has_right or (incoming == 'PERMIT' and written == 'BLOCK')
    return dict(path=path, right=int(has_right), incoming=incoming,
                written=written, contract_legal=legal)


def records():
    return [r for path in PATHS for right in (False, True)
            for incoming in ACTIONS if (r := one(path, right, incoming)) is not None]


def matrix_bytes():
    return ''.join(f"{r['path']}|{r['right']}|{r['incoming']}|{r['written']}|{int(r['contract_legal'])}\n"
                   for r in records()).encode('ascii')


class Tests(unittest.TestCase):
    def test_24_states(self):
        self.assertEqual(len(records()), 24)

    def test_12_invalid_no_right_writes(self):
        wrong = [r for r in records() if not r['contract_legal']]
        self.assertEqual(len(wrong), 12)
        self.assertTrue(all(r['right'] == 0 and r['incoming'] != 'PERMIT' for r in wrong))

    def test_veto_only_for_preexisting_permit_without_right(self):
        for r in records():
            if r['right'] == 0:
                self.assertEqual(r['contract_legal'], r['incoming'] == 'PERMIT')

    def test_redirect_self_with_write_is_continue(self):
        for incoming in ACTIONS:
            self.assertEqual(one('redirect_self', True, incoming)['written'], 'CONTINUE')

    def test_redirect_self_without_write_never_reaches_self_query(self):
        for incoming in ACTIONS:
            self.assertEqual(one('redirect_self', False, incoming)['written'], 'BLOCK')

    def test_no_write_branch_disallows_positive_write(self):
        self.assertIsNone(one('redirect_no_write', True, 'PERMIT'))
        self.assertIsNone(one('auth_no_write', True, 'PERMIT'))

    def test_stop_write_right_is_legal(self):
        self.assertTrue(all(one('callback_stop', True, a)['contract_legal'] for a in ACTIONS))

    def test_stop_no_right_is_conditional(self):
        self.assertEqual(sum(one('callback_stop', False, a)['contract_legal'] for a in ACTIONS), 1)

    def test_action_only_is_not_kernel_proof(self):
        self.assertNotIn('PID', matrix_bytes().decode())

    def test_digest_deterministic(self):
        self.assertEqual(hashlib.sha256(matrix_bytes()).hexdigest(), '9e1f244d647e0b471515b3b7096e93a94524ca9016d92efaee8d1fc567e376be')

    def test_source_hash_mutation_is_rejected(self):
        data = b'FWP_ACTION_BLOCK'
        self.assertNotEqual(git_blob(data), git_blob(data+b' '))

    def test_no_side_effect_imports(self):
        imports = [node for node in ast.walk(ast.parse(Path(__file__).read_text()))
                   if isinstance(node, (ast.Import, ast.ImportFrom))]
        names = []
        for node in imports:
            if isinstance(node, ast.Import): names.extend(alias.name for alias in node.names)
            else: names.append(node.module or '')
        self.assertTrue(set(names).isdisjoint({'ctypes', 'socket', 'subprocess', 'requests'}))


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--matrix':
        print(json.dumps(dict(cases=len(records()), contract_invalid=sum(not r['contract_legal'] for r in records()), sha256=hashlib.sha256(matrix_bytes()).hexdigest()), sort_keys=True))
    elif len(sys.argv) == 3 and sys.argv[1] == '--check-sources':
        print(json.dumps(dict(source_blobs={p:git_blob(v.encode()) for p,v in assert_pinned_sources(sys.argv[2]).items()}, cases=len(records()), invalid=sum(not r['contract_legal'] for r in records()), sha256=hashlib.sha256(matrix_bytes()).hexdigest()), sort_keys=True))
    else:
        unittest.main(verbosity=2)
