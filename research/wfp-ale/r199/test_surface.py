"""Independent static/ABI-surface negative gate. It does NOT compile or run Windows WFP."""
from pathlib import Path
import hashlib
import re
import tomllib
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "main.rs").read_text(encoding="utf-8")
MANIFEST = tomllib.loads((HERE / "Cargo.toml").read_text(encoding="utf-8"))
LOCK = tomllib.loads((HERE / "Cargo.lock").read_text(encoding="utf-8"))
ALLOWED = {
    "FwpmEngineOpen0", "FwpmEngineClose0", "FwpmFreeMemory0",
    "FwpmSubLayerGetByKey0", "FwpmCalloutGetByKey0", "FwpmFilterGetByKey0",
}


class Contract(unittest.TestCase):
    def test_fixed_allowlist(self):
        self.assertEqual(set(re.findall(r"\b(Fwpm\w+0)\s*\(", SOURCE)), ALLOWED)

    def test_no_mutation_surface(self):
        for forbidden in ("FwpmFilterAdd0", "FwpmFilterDeleteByKey0", "FwpmCalloutAdd0",
                          "FwpmSubLayerAdd0", "FwpmTransactionBegin0", "WSAIoctl",
                          "DeviceIoControl", "TcpStream", "socket(", "std::net"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, SOURCE)

    def test_no_native_claim(self):
        self.assertIn(r"\"kernel_proof\":false", SOURCE)
        self.assertIn(r"\"atomic\":false", SOURCE)
        self.assertIn("MANAGEMENT_READBACK_NOT_PROOF", SOURCE)
        self.assertIn("UNKNOWN", SOURCE)

    def test_no_success_assumed_for_error(self):
        self.assertIn("code == 0 && !owned.0.is_null()", SOURCE)
        self.assertIn("let registered = visible &&", SOURCE)

    def test_win_only_guard(self):
        self.assertIn("#[cfg(not(windows))]", SOURCE)
        self.assertIn("#[cfg(windows)]", SOURCE)
        self.assertIn("std::process::exit(2)", SOURCE)

    def test_four_exact_key_pairs(self):
        for suffix in ("f018", "f019", "f014", "f016"):
            self.assertRegex(SOURCE, rf"0x1649{suffix}_25b3_4e01_9ca1_5ca803010019")
        self.assertIn("0x1649f030_25b3_4e01_9ca1_5ca803010019", SOURCE)
        self.assertIn("(i as u128) << 96", SOURCE)

    def test_locked_dependency_graph(self):
        package = MANIFEST["package"]["name"]
        self.assertEqual(package, LOCK["package"][0]["name"])
        self.assertEqual(package, MANIFEST["bin"][0]["name"])
        self.assertEqual(MANIFEST['target']["cfg(windows)"]["dependencies"]["windows-sys"]["version"], "=0.61.2")
        self.assertEqual([(p["name"], p["version"]) for p in LOCK["package"]],
                         [(package, "0.0.1"), ("windows-link", "0.2.1"), ("windows-sys", "0.61.2")])
        for p in LOCK["package"][1:]:
            self.assertRegex(p["checksum"], "^[0-9a-f]{64}$")

    def test_intentional_nonatomicity(self):
        self.assertIn("Intentionally NO transaction", SOURCE)
        self.assertNotIn("FWPM_TXN_READ_ONLY", SOURCE)
        self.assertIn("FwpmEngineClose0(self.0)", SOURCE)


if __name__ == "__main__":
    print("R199 Rust SHA256", hashlib.sha256(SOURCE.encode()).hexdigest())
    unittest.main(verbosity=2)
