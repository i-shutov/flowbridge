#!/usr/bin/env python3
"""Offline exact Git blob lease regression: no WFP, driver, network, Windows changes."""
from __future__ import annotations
import hashlib
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'r103'/'r103_readonly_arbitration_inventory.rs'
HARNESS=ROOT/'r112'/'R112_WINDOWS_NATIVE_READONLY_CHECK.ps1'
PIN='06c677b484ef2cf5fa0330f819524dfa6b52e55a'
PRE_R123='49506ca07145c18947a0845f2a1a63b3de1f54ec'

def git_blob(data:bytes)->str:
    return hashlib.sha1(b'blob '+str(len(data)).encode('ascii')+b'\x00'+data).hexdigest()

def canonicalize_crlf(data:bytes)->bytes:
    # Equivalent to the strict R115 PS byte loop: only remove CR before LF.
    return data.replace(b'\r\n',b'\n')

class SourceLeaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=SOURCE.read_bytes()
        cls.ps=HARNESS.read_text(encoding='utf-8')

    def test_pinned_exact_checkout(self):
        self.assertEqual(git_blob(self.data), PIN)
        matches=re.findall(r"(?m)^\$expectedGitBlob\s*=\s*'([0-9a-f]{40})'\s*$",self.ps)
        self.assertEqual(matches,[PIN])
        self.assertNotEqual(PIN,PRE_R123)

    def test_reject_old_pinned_source(self):
        self.assertNotEqual(git_blob(self.data), PRE_R123)

    def test_crlf_canonical_source_accepted(self):
        self.assertEqual(git_blob(canonicalize_crlf(self.data.replace(b'\n',b'\r\n'))),PIN)

    def test_100_byte_mutations_rejected(self):
        positions=[(i*len(self.data)//100) for i in range(100)]
        self.assertEqual(len(set(positions)),100)
        for pos in positions:
            modified=bytearray(self.data)
            modified[pos]^=1
            self.assertNotEqual(git_blob(canonicalize_crlf(modified)),PIN, msg=f'offset={pos}')

    def test_truncated_and_extra_bytes_rejected(self):
        for changed in [self.data[:-1],self.data+b'\n',b'\xef\xbb\xbf'+self.data]:
            self.assertNotEqual(git_blob(canonicalize_crlf(changed)),PIN)

    def test_ps_rejects_mismatch_after_normalization(self):
        self.assertIn('if ($normalizedBlob -ne $expectedGitBlob)',self.ps)
        self.assertIn("throw 'Source Git blob mismatch after exact CRLF normalization",self.ps)
        self.assertIn('$resolved = $canonicalPath',self.ps)
        self.assertIn('$report.source_compilation_sha256',self.ps)
        self.assertIn('$report.source_git_blob_observed = Git-BlobSha1 $resolved',self.ps)
        self.assertNotIn('$expectedGitBlob = \''+PRE_R123+'\'',self.ps)

    def test_scope_is_only_metadata_by_default(self):
        self.assertIn('[switch]$RunUnitTests',self.ps)
        self.assertIn('[switch]$RunReadOnlyBfe',self.ps)
        self.assertIn('if ($RunReadOnlyBfe -and -not $RunUnitTests)',self.ps)
        self.assertIn('no_direct_proof = $false',self.ps)

if __name__=='__main__':
    unittest.main(verbosity=2)
