#!/usr/bin/env python3
"""R139 byte/delimiter regression; not Windows PowerShell AST validation."""
from pathlib import Path
import hashlib
import unittest

ROOT = Path(__file__).resolve().parent
ORIG = ROOT / 'FlowBridge-R139-SourceGate.ps1'
FIX = ROOT / 'FlowBridge-R139-SourceGate-PS51-v2.ps1'
OLD_SHA = 'd7545306aad0e85da565bc679c98037aa51797f9b13d36558076f39fd7efe43b'
NEW_SHA = '2b66655e819d7a1218103527e141ab0eed1fb641539fdf416b5052945ae32c0d'

def scan(s):
    stack, errors, state, lineno = [], [], 'code', 1
    i = 0
    while i < len(s):
        c = s[i]
        nxt = s[i + 1] if i + 1 < len(s) else ''
        if state == 'comment':
            if c == '\n': state = 'code'
        elif state == 'blockcomment':
            if c == '#' and nxt == '>':
                state = 'code'
                i += 1
        elif state == 'single':
            if c == "'":
                if nxt == "'": i += 1
                else: state = 'code'
        elif state == 'double':
            if ord(c) == 96: i += 1
            elif c == '"': state = 'code'
        else:
            if c == '#': state = 'comment'
            elif c == '<' and nxt == '#':
                state = 'blockcomment'
                i += 1
            elif c == "'": state = 'single'
            elif c == '"': state = 'double'
            elif c in '([{': stack.append((c, lineno))
            elif c in ')]}':
                expected = {')':'(', ']':'[', '}':'{'}[c]
                if not stack or stack[-1][0] != expected:
                    errors.append((lineno, c))
                    break
                stack.pop()
        if c == '\n': lineno += 1
        i += 1
    return errors, stack, state

class R139PowerShellStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = ORIG.read_bytes()
        cls.new = FIX.read_bytes()
    def test_original_sha(self):
        self.assertEqual(hashlib.sha256(self.old).hexdigest(), OLD_SHA)
    def test_new_sha(self):
        self.assertEqual(hashlib.sha256(self.new).hexdigest(), NEW_SHA)
    def test_original_is_malformed(self):
        self.assertEqual(scan(self.old.decode('utf-8'))[0][0][0], 79)
    def test_fixed_is_balanced(self):
        self.assertEqual(scan(self.new.decode('utf-8')), ([], [], 'code'))
    def test_exact_two_character_change_only(self):
        a, b = self.old.decode('utf-8').splitlines(), self.new.decode('utf-8').splitlines()
        self.assertEqual(len(a), len(b))
        changed = [(i + 1, old, new) for i, (old, new) in enumerate(zip(a, b)) if old != new]
        self.assertEqual([i for i, _, _ in changed], [79, 80])
        for _, old, new in changed:
            self.assertEqual(old.replace("'connect(s.0')))", "'connect(s.0'))"), new)
        self.assertEqual(len(self.old) - len(self.new), 2)
    def test_source_contract_unchanged(self):
        for token in (b'Git-Blob $bytes', b'if($git -cne $entry.Value)',
                      b'$report.source_receipt_pipeline_pass=$receipt',
                      b'$report.dynamic_policy_lifetime_gap',
                      b'$report.action_rights_blocker',
                      b"R139_SOURCE_RECEIPT_VALIDATED_RELEASE_NO_GO",
                      b'bfe_queried = $false', b'socket_created = $false'):
            self.assertIn(token, self.new)
    def test_host_parser_still_required(self):
        self.assertTrue(self.new.startswith(b'#requires -Version 5.1'))
        self.assertIn(b'$exitCode=3', self.new)

if __name__ == '__main__':
    unittest.main(verbosity=2)
