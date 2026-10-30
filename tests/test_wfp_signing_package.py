"""No Windows or credentials required: negative signing-package preflight tests."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from wfp_signing_package import PreflightError, prepare  # noqa: E402

SHA = "a" * 40
INF = r'''[Version]
Signature="$WINDOWS NT$"
CatalogFile=FlowBridgeWfp.cat
DriverVer=10/28/2026,0.2.0.0
PnpLockdown=1
[DriverService]
ServiceType=1
StartType=3
ServiceBinary=%13%\FlowBridgeWfp.sys
'''


class SigningInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.pkg = root / "FlowBridgeWfp"
        self.pkg.mkdir()
        (self.pkg / "FlowBridgeWfp.sys").write_bytes(b"MZ-unsigned-driver")
        (self.pkg / "FlowBridgeWfp.inf").write_text(INF, encoding="utf-8")
        (self.pkg / "flowbridgewfp.cat").write_bytes(b"unsigned catalog")
        self.pdb = root / "FlowBridgeWfp.pdb"
        self.pdb.write_bytes(b"debug symbols")
        self.output = root / "candidate"

    def build(self, source_sha=SHA):
        return prepare(self.pkg, self.pdb, self.output, source_sha, create_cab=False)

    def test_valid_wdk_inputs_are_staged_and_clearly_unsigned(self):
        report = self.build()
        self.assertTrue(report["wdk_package_inputs_checked"])
        self.assertFalse(report["cabinet_generated_and_byte_verified"])
        self.assertFalse(report["microsoft_hardware_signature_verified"])
        self.assertFalse(report["driver_installed_or_loaded"])
        self.assertEqual(report["files"]["FlowBridgeWfp.sys"]["size_bytes"], 18)
        self.assertIn(".Set DestinationDir=FlowBridgeWfp", (self.output / "FlowBridgeWfp.ddf").read_text())
        self.assertEqual(len(list((self.output / "staging" / "FlowBridgeWfp").iterdir())), 4)

    def test_missing_catalog_fails_closed(self):
        (self.pkg / "flowbridgewfp.cat").unlink()
        with self.assertRaisesRegex(PreflightError, "exactly one FlowBridgeWfp.cat"):
            self.build()

    def test_inf_wrong_service_fails_closed(self):
        (self.pkg / "FlowBridgeWfp.inf").write_text(INF.replace("FlowBridgeWfp.sys", "another.sys"))
        with self.assertRaisesRegex(PreflightError, "ServiceBinary"):
            self.build()

    def test_malformed_source_sha_rejected(self):
        with self.assertRaisesRegex(PreflightError, "Full 40-character"):
            self.build("main")

    def test_stale_output_refused(self):
        self.output.mkdir()
        with self.assertRaisesRegex(PreflightError, "stale"):
            self.build()

    def test_symlink_is_never_packaged(self):
        (self.pkg / "FlowBridgeWfp.sys").unlink()
        (self.pkg / "FlowBridgeWfp.sys").symlink_to(self.pdb)
        with self.assertRaisesRegex(PreflightError, "symlink"):
            self.build()

    def test_non_pe_driver_rejected(self):
        (self.pkg / "FlowBridgeWfp.sys").write_bytes(b"fake-driver")
        with self.assertRaisesRegex(PreflightError, "PE image"):
            self.build()

    def test_wrong_pdb_basename_rejected(self):
        other = self.pdb.with_name("unrelated.pdb")
        other.write_bytes(b"debug")
        with self.assertRaisesRegex(PreflightError, "FlowBridgeWfp.pdb"):
            prepare(self.pkg, other, self.output, SHA, create_cab=False)


if __name__ == "__main__":
    unittest.main()
