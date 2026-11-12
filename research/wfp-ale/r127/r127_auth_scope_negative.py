#!/usr/bin/env python3
"""Deterministic WFP AUTH_CONNECT predicate counterexamples; NO WINDOWS API calls.

All test cases are synthetic. This proves coverage relationships of proposed BFE
predicates only, not kernel provenance, callback delivery, or no-leak safety.
"""
import hashlib
import itertools
import json
import unittest

ORIGINAL = ("selected", "unrelated", "missing")
CURRENT = ("selected", "broker", "third_party", "missing")
DEST = ("loopback", "external", "unknown")
FAMILY = (4, 6)
PROTOCOL = ("tcp", "udp")


def classify(original, current, dest, family, protocol):
    assert family in FAMILY
    # Current R19 policy: ORIGINAL_APP_ID + TCP at AUTH_CONNECT_V4/V6.
    legacy = original == "selected" and protocol == "tcp"
    # Counterfactual only: two OR-ed filters, NOT an implementation proposal.
    by_current = current == "selected" and protocol == "tcp"
    by_orig_local = (original == "selected" and dest == "loopback"
                     and protocol == "tcp")
    split = by_current or by_orig_local
    return {"legacy": int(legacy), "split": int(split),
            "current_rule": int(by_current), "local_rule": int(by_orig_local),
            "overlap": int(by_current and by_orig_local)}


def cases():
    for original, current, dest, family, protocol in itertools.product(
            ORIGINAL, CURRENT, DEST, FAMILY, PROTOCOL):
        key = {"original": original, "current": current, "dest": dest,
               "family": family, "protocol": protocol}
        yield {**key, **classify(**key)}


def fingerprint():
    rows = list(cases())
    canonical = "".join(json.dumps(x, sort_keys=True, separators=(",", ":"))
                        + "\n" for x in rows).encode("utf-8")
    return len(rows), hashlib.sha256(canonical).hexdigest(), rows


class WfpAuthPredicateCuts(unittest.TestCase):
    def test_selected_direct_is_not_missed_by_split(self):
        for family in FAMILY:
            r = classify("selected", "selected", "external", family, "tcp")
            self.assertEqual((r["legacy"], r["split"]), (1, 1))

    def test_record_carrying_broker_external_selfblock_counterfactual(self):
        for family in FAMILY:
            r = classify("selected", "broker", "external", family, "tcp")
            self.assertEqual((r["legacy"], r["split"]), (1, 0))

    def test_redirected_to_loopback_with_broker_current_remains_scoped(self):
        for family in FAMILY:
            r = classify("selected", "broker", "loopback", family, "tcp")
            self.assertEqual((r["legacy"], r["split"]), (1, 1))

    def test_alternate_proxy_external_is_not_scoped_by_split(self):
        for family in FAMILY:
            r = classify("selected", "third_party", "external", family, "tcp")
            self.assertEqual((r["legacy"], r["split"]), (1, 0))

    def test_absent_original_appid_proves_no_redirected_origin(self):
        for family in FAMILY:
            r = classify("missing", "broker", "loopback", family, "tcp")
            self.assertEqual((r["legacy"], r["split"]), (0, 0))

    def test_any_udp_is_outside_tcp_scope(self):
        for row in cases():
            if row["protocol"] == "udp":
                self.assertEqual((row["legacy"], row["split"]), (0, 0))

    def test_overlap_cannot_assume_one_terminal_callout(self):
        for family in FAMILY:
            r=classify("selected", "selected", "loopback", family, "tcp")
            self.assertEqual((r["current_rule"], r["local_rule"], r["overlap"]), (1,1,1))

    def test_exhaustive_structure_and_nonidentity(self):
        n, _, rows = fingerprint()
        self.assertEqual(n, 144)
        self.assertTrue(any(x["legacy"] and not x["split"] for x in rows))
        self.assertTrue(any(x["split"] and not x["legacy"] for x in rows))
        for r in rows:
            self.assertEqual(r["split"], int(bool(r["current_rule"] or r["local_rule"])))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(WfpAuthPredicateCuts)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    n, sha, rows = fingerprint()
    stats = {k: sum(r[k] for r in rows)
             for k in ("legacy", "split", "current_rule", "local_rule", "overlap")}
    stats["legacy_only"] = sum(r["legacy"] and not r["split"] for r in rows)
    stats["split_only"] = sum(r["split"] and not r["legacy"] for r in rows)
    print(json.dumps({"cases": n, "sha256": sha, "counts": stats, "tests": result.testsRun,
                      "pass": result.wasSuccessful()}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
