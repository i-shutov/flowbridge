"""Source-bound fail-closed WFP hard-permit veto regression.

These checks inspect the real production classify callbacks and deliberately
restore bypass variants. They DO NOT execute a WFP callback or establish G2.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native/windows/wfp/driver/driver.c"
RIGHT = "FWPS_RIGHT_ACTION_WRITE"
PERMIT = "FWP_ACTION_PERMIT"
BLOCK = "FWP_ACTION_BLOCK"


def function_span(source: str, name: str) -> tuple[int, int]:
    prefix = r"static\s+void\s+(?:NTAPI\s+)?"
    match = re.search(prefix + re.escape(name) + r"\s*\(", source)
    if match is None:
        raise AssertionError(f"MISSING_PRODUCT_FUNCTION_{name}")
    begin = source.find("{", match.end())
    if begin < 0:
        raise AssertionError(f"MISSING_FUNCTION_BODY_{name}")
    depth = 0
    for i in range(begin, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return begin, i + 1
    raise AssertionError(f"UNCLOSED_PRODUCT_FUNCTION_{name}")


def mutate_function(source: str, name: str, old: str, new: str) -> str:
    begin, end = function_span(source, name)
    body = source[begin:end]
    if body.count(old) != 1:
        raise AssertionError(f"MUTATION_ANCHOR_NOT_UNIQUE_{name}")
    return source[:begin] + body.replace(old, new, 1) + source[end:]


def audit(source: str) -> None:
    # The block helper must enforce a terminal veto, never just log a failure.
    start, end = function_span(source, "FbBlock")
    helper = source[start:end]
    if not re.search(r"out->actionType\s*=\s*FWP_ACTION_BLOCK\s*;", helper):
        raise AssertionError("FB_BLOCK_NOT_BLOCKING")
    if not re.search(r"out->rights\s*&=\s*~FWPS_RIGHT_ACTION_WRITE\s*;", helper):
        raise AssertionError("FB_BLOCK_NOT_TERMINAL")

    # Both AUTH_CONNECT and CONNECT_REDIRECT MUST veto a prior hard PERMIT.
    # Under no ACTION_WRITE a previous BLOCK cannot be promoted to PERMIT.
    for name in ("FbAuthClassify", "FbClassify"):
        begin, end = function_span(source, name)
        body = source[begin:end]
        guarded = re.search(
            r"if\s*\(\s*!\s*\(\s*out->rights\s*&\s*"
            r"FWPS_RIGHT_ACTION_WRITE\s*\)\s*\)\s*\{"
            r"(?P<inside>[^{}]*)\}",
            body,
        )
        if guarded is None:
            raise AssertionError(f"{name}_NO_RIGHTS_GUARD")
        inside = guarded.group("inside")
        veto = re.search(
            r"if\s*\(\s*out->actionType\s*==\s*FWP_ACTION_PERMIT\s*\)"
            r"\s*FbBlock\s*\(\s*out\s*\)\s*;",
            inside,
        )
        ret = re.search(r"\breturn\s*;", inside)
        if veto is None or ret is None or veto.start() > ret.start():
            raise AssertionError(f"{name}_HARD_PERMIT_NOT_VETOED")
        if re.search(r"out->actionType\s*=\s*FWP_ACTION_PERMIT\s*;", body[:guarded.end()]):
            raise AssertionError(f"{name}_PERMIT_BEFORE_RIGHTS_GATE")


class TestWfpHardPermitVeto(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.original = SOURCE.read_text(encoding="utf-8")

    def test_product_has_both_terminating_vetoes(self) -> None:
        audit(self.original)

    def test_six_hostile_mutations_rejected(self) -> None:
        original = self.original
        guard = "if (!(out->rights & FWPS_RIGHT_ACTION_WRITE))"
        veto = "if (out->actionType == FWP_ACTION_PERMIT) FbBlock(out);"
        mutated = (
            mutate_function(original, "FbClassify", veto, "/* no hard-permit veto */"),
            mutate_function(original, "FbAuthClassify", veto, "/* auth hard permit escaped */"),
            mutate_function(original, "FbClassify", veto,
                            "if (out->actionType != FWP_ACTION_PERMIT) FbBlock(out);"),
            mutate_function(original, "FbClassify", guard,
                            "if (out->rights & FWPS_RIGHT_ACTION_WRITE)"),
            mutate_function(original, "FbClassify", veto, "return; " + veto),
            mutate_function(original, "FbBlock",
                            "out->actionType = FWP_ACTION_BLOCK;",
                            "out->actionType = FWP_ACTION_PERMIT;"),
        )
        for i, variant in enumerate(mutated, 1):
            with self.subTest(mutant=i):
                with self.assertRaises(AssertionError):
                    audit(variant)


if __name__ == "__main__":
    unittest.main()
