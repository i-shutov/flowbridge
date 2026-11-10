"""Read-only R87 contract check. No OS calls, drivers, network or policy writes.

The generic 2021 Microsoft per-layer table and the 2024 specialized redirect
instructions conflict on two ALE_AUTH_CONNECT metadata fields. This program
reproduces the source's hard conjunction and quantifies the documentation gap;
it is not a Windows reachability proof.
"""
from pathlib import Path
import hashlib
import os
import re
import unittest

SRC = Path(os.environ.get("R87_R19_SOURCE", Path(__file__).resolve().parents[1] / "kernel-r19/kernel/src/redirect.rs"))
GENERIC = frozenset(("FWPS_METADATA_FIELD_FLOW_HANDLE", "FWPS_METADATA_FIELD_PROCESS_PATH",
  "FWPS_METADATA_FIELD_TOKEN", "FWPS_METADATA_FIELD_PROCESS_ID", "FWPS_METADATA_FIELD_RESERVED",
  "FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE", "FWPS_METADATA_FIELD_COMPARTMENT_ID",
  "FWPS_METADATA_FIELD_COMPLETION_HANDLE", "FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE",
  "FWPS_METADATA_FIELD_REMOTE_SCOPE_ID", "FWPS_METADATA_FIELD_PACKET_DIRECTION",
  "FWPS_METADATA_FIELD_PARENT_ENDPOINT_HANDLE", "FWPS_METADATA_FIELD_ICMP_ID_AND_SEQUENCE",
  "FWPS_METADATA_FIELD_SUB_PROCESS_TAG"))
SPECIAL = frozenset(("FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID", "FWPS_METADATA_FIELD_ORIGINAL_DESTINATION"))

def load_source():
    src = SRC.read_text(encoding="utf-8")
    body = src.split("unsafe fn auth_check(", 1)[1]
    needed = re.search(r"let\s+needed\s*=\s*([\s\S]*?);", body)
    assert needed, "cannot find authenticating metadata requirement"
    fields = frozenset(re.findall(r"FWPS_METADATA_FIELD_[A-Z_]+", needed.group(1)))
    return body, fields

def decision(required, provided):
    return required.issubset(provided)

def summary():
    body, required = load_source()
    gap = sorted(required - GENERIC)
    rows = ["required=" + ",".join(sorted(required)),
            "generic_gap=" + ",".join(gap),
            "special_doc_covers=" + ",".join(sorted(set(gap) & SPECIAL)),
            "generic_complete=" + str(decision(required, GENERIC)).lower(),
            "special_plus_generic_complete=" + str(decision(required, GENERIC | SPECIAL)).lower()]
    return {"required": sorted(required), "generic_gap": gap, "digest": hashlib.sha256(("\n".join(rows)+"\n").encode()).hexdigest(), "rows": rows}

class R87NegativeTests(unittest.TestCase):
    def test_source_two_ip_families_and_conjunction(self):
        body, fields = load_source()
        self.assertIn("FWPS_LAYER_ALE_AUTH_CONNECT_V4", body)
        self.assertIn("FWPS_LAYER_ALE_AUTH_CONNECT_V6", body)
        self.assertRegex(body, r"m\.currentMetadataValues\s*&\s*needed\s*!=\s*needed")
        self.assertEqual(len(fields), 4)

    def test_generic_layer_table_does_not_cover_source_guard(self):
        self.assertEqual(summary()["generic_gap"], sorted(SPECIAL))
        self.assertFalse(decision(set(summary()["required"]), GENERIC))

    def test_specialized_guide_claims_both_gap_fields(self):
        self.assertTrue(decision(set(summary()["required"]), GENERIC | SPECIAL))
        self.assertTrue(SPECIAL.isdisjoint(GENERIC))

    def test_missing_either_is_terminal_for_source_guard(self):
        needed = set(summary()["required"])
        for missing in SPECIAL:
            with self.subTest(missing=missing):
                self.assertFalse(decision(needed, needed - {missing}))
                self.assertTrue(decision(needed, needed))

if __name__ == "__main__":
    unittest.main(exit=False, verbosity=2)
    print("R87_CONTRACT", summary())
