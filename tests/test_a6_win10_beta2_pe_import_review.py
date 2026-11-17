"""Adversarial PE import allowlist and no-release controls."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

FILE=Path(__file__).resolve().parents[1]/"tools"/"a6_win10_beta2_pe_import_review.py"
spec=importlib.util.spec_from_file_location("flowbridge_pe_a6",FILE)
pe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(pe)

class TestOriginalPEImports(unittest.TestCase):
    def test_parses_case_insensitively_and_only_allowed_runtime_names(self):
        names=pe.parse_imports("  DLL Name: KERNEL32.dll\n  DLL Name: flowbridge_ffi.dll\n")
        self.assertEqual(names,["flowbridge_ffi.dll","kernel32.dll"])

    def test_rejects_external_vendor_dll(self):
        for name in ["VCRUNTIME140.dll","MSVCP140.dll","python313.dll","EVIL.dll"]:
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,"unexpected_dynamic_import"):
                pe.parse_imports("DLL Name: KERNEL32.dll\nDLL Name: "+name+"\n")

    def test_rejects_empty_or_unsupported_output(self):
        with self.assertRaisesRegex(ValueError,"no_pe_imports"):
            pe.parse_imports("not a PE\n")

    def test_sha_must_match_before_objdump_execution(self):
        with patch.object(Path,"is_file",return_value=True), \
             patch.object(Path,"is_symlink",return_value=False), \
             patch.object(Path,"read_bytes",return_value=b"forged installer"):
            with self.assertRaisesRegex(ValueError,"exact_binary_sha_mismatch"), \
                 patch.object(subprocess,"run",side_effect=AssertionError("should not execute")):
                pe.examine(Path("fake"))

if __name__=="__main__":
    unittest.main()
