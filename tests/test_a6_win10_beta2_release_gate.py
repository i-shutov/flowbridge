"""Adversarial offline A6 controls; no owner-private ZIPs enter CI."""
from __future__ import annotations
from io import BytesIO
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

FILE = Path(__file__).resolve().parents[1] / "tools" / "a6_win10_beta2_release_gate.py"
spec = importlib.util.spec_from_file_location("flowbridge_a6", FILE)
a6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a6)

def make_zip(files: dict[str, bytes]) -> bytes:
    out = BytesIO()
    with ZipFile(out, "w", ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return out.getvalue()

class TestA6HardGates(unittest.TestCase):
    def test_rejects_zip_traversal_and_drive_paths(self):
        for path in ("../escape","/abs/secret","./relative","sub/../escape",
                     "C:/Windows/secret","dir\\secret"):
            with self.subTest(path=path), self.assertRaisesRegex(a6.GateError, "zip_path"):
                a6.archive(make_zip({path: b"bad"}))

    def test_duplicate_casefold_refused(self):
        data = make_zip({"ssh/Report.JSON": b"a", "ssh/report.json": b"b"})
        with self.assertRaisesRegex(a6.GateError, "zip_casefold_duplicate"):
            a6.archive(data)

    def test_symlink_refused(self):
        out = BytesIO()
        with ZipFile(out, "w") as z:
            link = ZipInfo("id_ed25519")
            link.create_system = 3
            link.external_attr = 0o120777 << 16
            z.writestr(link, b"/some/private/ssh.key")
        with self.assertRaisesRegex(a6.GateError, "zip_symlink"):
            a6.archive(out.getvalue())

    def test_rejects_undeclared_or_tampered_owner_files(self):
        record = {"path": "report.json", "sha256": a6.digest(b"safe"), "bytes":4}
        files = {"report.json": b"safe",
                 "sha256-manifest.json": json.dumps({"files":[record]}).encode()}
        a6.manifest(files, 1)
        with self.assertRaisesRegex(a6.GateError, "manifest_digest"):
            a6.manifest({**files, "report.json": b"evil"}, 1)
        with self.assertRaisesRegex(a6.GateError, "manifest_extra"):
            a6.manifest({**files, "extra.key": b"PRIVATE"}, 1)

    def test_positive_socks_evidence_requires_domain_eof_and_no_direct(self):
        e = {"ok":True,"atyp":"DOMAINNAME","domain":"localhost",
             "hello":"0500","reply":"05000001","payload_hex":a6.ECHO,
             "up_hex":a6.ECHO,"down_hex":a6.ECHO,"client_eof":True,
             "target_eof":True,"direct_pending":False}
        a6.positive_echo(e, "bad_echo")
        for key, value in (("atyp","IPV4"),("direct_pending",True),
                           ("reply","05010001"),("client_eof",False),
                           ("payload_hex","0000")):
            with self.subTest(key=key), self.assertRaisesRegex(a6.GateError, "bad_echo"):
                a6.positive_echo({**e,key:value}, "bad_echo")

    def test_restoration_requires_complete_acl_and_no_processes(self):
        rows = [{"hash_match":True,"acl_match":True,"time_match":True,
                 "attributes_match":True,"count_match":True}]*4
        files = {"restore-checks.json":json.dumps(rows).encode(),
                 "cleanup.json":json.dumps({"registry_equal":True,
                    "escrow_restored":True,"processes":[],
                    "test_install_exists":False,"uninstall_key_exists":False}).encode()}
        a6.restored(files)
        with self.assertRaisesRegex(a6.GateError,"restore_file_evidence"):
            rows[0] = {**rows[0],"acl_match":False}
            a6.restored({**files,"restore-checks.json":json.dumps(rows).encode()})

    def test_never_grants_release_or_wfp_on_technical_pass(self):
        with patch.object(a6,"original_kit", return_value={"status":"PASS_ORIGINAL_BYTES"}):
            result = a6.review(Path("dummy"))
            for key in ("a5_legal_and_native_review_accepted","a6_release_approved",
                        "a7_publication_approved","publisher_release_approved",
                        "release_accepted","wfp_g2_accepted"):
                self.assertFalse(result[key], key)
            self.assertEqual(result["scope"],
                             "Windows 10 Pro 22H2 x64 ONLY; Win11/macOS deferred, not PASSED")
            with self.assertRaisesRegex(a6.GateError, "owner_evidence_incomplete"):
                a6.review(Path("dummy"), b"V4 only", None)

if __name__ == "__main__":
    unittest.main()
