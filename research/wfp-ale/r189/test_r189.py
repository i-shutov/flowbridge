#!/usr/bin/env python3
"""R189 offline negative checks; synthetic, not real Windows evidence."""
import unittest
from pathlib import Path
from commit_fence_negative import run

class FenceTests(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(run()['counts'], dict(rows=576,naive_green=72,stale_or_unknown=68,unsafe_certificate=72))
    def test_sha(self):
        self.assertEqual(run()['matrix_sha256'], '7c2b3d705aae19a6c0b97e0dabcb42628293890b3e82d63f216b1daf0029c362')
    def test_no_native_claim(self):
        self.assertIs(run()['native_windows'],False)
    def test_certificate_mutation_rejected(self):
        source=(Path(__file__).parent/'commit_fence_negative.py').read_text()
        self.assertIn('no_direct_certificate=0',source)
        mutant=source.replace('no_direct_certificate=0','no_direct_certificate=1')
        self.assertNotEqual(mutant,source)
        globals_={'__name__':'r189_mutant'}
        exec(compile(mutant,'r189_mutant.py','exec'),globals_)
        with self.assertRaises(AssertionError): globals_['run']()
    def test_all_selected_tcp_not_attested(self):
        x=run()
        self.assertEqual(x['counts']['naive_green'],x['counts']['unsafe_certificate'])

if __name__=='__main__': unittest.main()
