"""R210 minimal independent source/negative gate for the published patch."""
from pathlib import Path
import unittest
P=Path(__file__).with_name('R210_R203v6_PINNED_R209.diff').read_text()
R='9ead09f9001c02444975fab37caee03ed4e55308'
FILES={
 'research/wfp-ale/r209/R209_PROXY_AUTH_SELF_BLOCK_NO_GO.md':'f55dc3dcb8f6ecd9c6b97f23ca2712a5ca7b9b45',
 'research/wfp-ale/r209/r209_self_block_negative.py':'8824be431e526429b8d221c3b2c90d56c3c704aa',
 'research/wfp-ale/r209/r209_self_block_oracle.mjs':'f4ab7d61164672e85fdd086684b13087bb08baec',
}
class T(unittest.TestCase):
 def test_exact_commit_pin(self):self.assertIn("$r209Commit = '"+R+"'",P)
 def test_three_full_blob_pins(self):
  for name,sha in FILES.items():self.assertIn("'"+name+"' = '"+sha+"'",P)
 def test_reject_count(self):self.assertIn('$changes.Count -ne $r209Blobs.Count',P)
 def test_reject_path(self):self.assertIn('$r209Blobs.Contains($entry)',P)
 def test_reject_blob(self):self.assertIn('$blob -cne $r209Blobs[$entry]',P)
 def test_no_generic_prefix(self):self.assertNotIn("'research/wfp-ale/r209/'",P)
 def test_allow_after_pin(self):self.assertIn('      continue\n+    }',P)
 def test_unchanged_legacy_prefix(self):self.assertIn("$allowedPrefix = @('research/wfp-ale/r203/','research/wfp-ale/r204/','research/wfp-ale/r205/')",P)
if __name__=='__main__':unittest.main(verbosity=2)
