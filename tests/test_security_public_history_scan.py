"""Mutation tests for redacted Git-history and private ZIP audit."""
from __future__ import annotations
from io import BytesIO
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from zipfile import ZipFile

FILE=Path(__file__).resolve().parents[1]/"tools"/"security"/"scan_public_history.py"
s=importlib.util.spec_from_file_location("flowbridge_security_inventory", FILE)
audit=importlib.util.module_from_spec(s)
s.loader.exec_module(audit)

class TestSecurityInventory(unittest.TestCase):
    def test_match_without_exposing_secret_value_or_filename(self):
        fake=b"ghp_"+b"Z"*36
        self.assertEqual(audit.match_kinds(fake),["github_token_classic"])
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"evidence.zip"
            with ZipFile(out,"w") as z:
                z.writestr("private/fake-token.txt",fake)
            r=audit.scan_zip(out)
            self.assertEqual(r["finding_rule_counts"],{"github_token_classic":1})
            self.assertNotIn(fake.decode(),json.dumps(r))
            self.assertNotIn("fake-token.txt",json.dumps(r))

    def test_only_exact_synthetic_fixture_is_exempt_not_generic_token_patterns(self):
        # Construct synthetic fixture bytes dynamically; never add a
        # complete token-looking literal to the public source tree.
        fixture = b"gh" + b"p_SYNTHETICSECRETDO_NOT_LOG_THIS_VALUE123456789"
        real_shape = b"gh" + b"p_" + b"Z" * 36
        self.assertEqual(audit.match_kinds(fixture), [])
        self.assertEqual(audit.match_kinds(fixture + b" " + real_shape),
                         ["github_token_classic"])
        self.assertEqual(fixture, audit.EXACT_SYNTHETIC_FIXTURE)

    def test_detects_deleted_old_git_blob_without_outputting_value(self):
        with tempfile.TemporaryDirectory() as temp:
            repo=Path(temp)
            subprocess.run(["git","init","-q",str(repo)],check=True)
            for key,val in [("user.name","Test"),("user.email","test@example.invalid")]:
                subprocess.run(["git","-C",str(repo),"config",key,val],check=True)
            private=b"-----BEGIN "+b"OPENSSH PRIVATE KEY-----"+b"\nSYNTHETIC_DATA_ONLY\n"
            (repo/"private.key").write_bytes(private)
            subprocess.run(["git","-C",str(repo),"add","."],check=True)
            subprocess.run(["git","-C",str(repo),"commit","-qm","fixture add"],check=True)
            (repo/"private.key").unlink()
            subprocess.run(["git","-C",str(repo),"add","-u"],check=True)
            subprocess.run(["git","-C",str(repo),"commit","-qm","fixture delete"],check=True)
            r=audit.scan_git(repo)
            self.assertEqual(r["finding_rule_counts"],{"private_key_pem":1})
            self.assertNotIn("SYNTHETIC_DATA_ONLY",json.dumps(r))
            self.assertNotIn("private.key",json.dumps(r))

    def test_rejects_zip_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp)/"evil.zip"
            with ZipFile(out,"w") as z:
                z.writestr("../escape",b"SECRET")
            with self.assertRaisesRegex(RuntimeError,"unsafe_zip_member"):
                audit.scan_zip(out)

    def test_oversized_data_are_not_falsely_called_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            src=Path(temp)/"large.zip"
            with ZipFile(src,"w") as z:
                z.writestr("oversized.bin",b"x"*(audit.MAX_ITEM+1))
            r=audit.scan_zip(src)
            self.assertEqual(r["skipped_large_files"],1)
            self.assertEqual(r["scanned_files"],0)

if __name__=="__main__":
    unittest.main()
