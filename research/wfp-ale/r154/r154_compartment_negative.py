#!/usr/bin/env python3
"""R154: offline compartment-provenance negative model. No Windows APIs.

This models the observable fields consumed by R19 Book::attest under explicit
hypotheses. It does not imply that Windows reuses a transport endpoint handle
across compartments, or that any packet was permitted.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path

PINS = {
    "kernel/src/handoff.rs": ("e1d17217db50362ba9c4efc83af820b6beb094cf", [
        "pub struct Origin { pub pid:u64, pub epoch:u64, pub key:u64, pub endpoint:u64, pub generation:u64 }",
        "pub fn attest(&mut self, origin:Origin, destination:Destination, now:u64)->bool",
        "slot.context.matches_origin(origin)",
    ]),
    "kernel/src/redirect.rs": ("a093f049d162987981a957aac90db1014bc6ff09", [
        "pub unsafe fn classify(", "unsafe fn auth_check(",
        "endpoint:m.transportEndpointHandle", "route.book.attest(identity,original_destination,now())",
    ]),
    "policy_windows.rs": ("acf60334320d970f58af3349ee75fbaa59826602", [
        "FWPM_CONDITION_ALE_ORIGINAL_APP_ID", "FWPM_CONDITION_IP_PROTOCOL",
    ]),
}


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def source_gate(root):
    """Exact source gate when an original Git checkout is available."""
    for relative, (expected, markers) in PINS.items():
        raw = (root / relative).read_bytes()
        if git_blob(raw) != expected:
            raise RuntimeError("SOURCE_BLOB_MISMATCH:" + relative)
        text = raw.decode("utf-8")
        for marker in markers:
            if marker not in text:
                raise RuntimeError("SOURCE_MARKER_MISSING:" + relative + ":" + marker)
        if relative.endswith("handoff.rs"):
            origin = text.split("pub struct Origin {", 1)[1].split("}", 1)[0]
            if "compartment" in origin:
                raise RuntimeError("ORIGIN_SCHEMA_CHANGED")
        if relative.endswith("redirect.rs"):
            auth = text.split("unsafe fn auth_check(", 1)[1]
            if "COMPARTMENT_ID" in auth or "compartmentId" in auth:
                raise RuntimeError("AUTH_COMPARTMENT_REVIEW_REQUIRED")


def outcome(family, owner_live, epoch_equal, endpoint_equal, compartment,
            appid_equal, action_write):
    # Fixed simulated selected PID, original destination, source port, key,
    # generation and original appId. Different or unavailable compartment is
    # intentionally NOT an input in the source R19 Origin/Context equality.
    eligible = owner_live and epoch_equal and endpoint_equal and appid_equal and action_write
    strict = eligible and compartment == "equal"
    if eligible and not strict:
        return "COMPARTMENT_UNBOUND_CONDITIONAL"
    if strict:
        return "MATCHED_MODEL_ONLY"
    return "OTHER_REQUIRED_FIELD_REJECTED"


def run():
    rows = []
    counts = {x: 0 for x in ("COMPARTMENT_UNBOUND_CONDITIONAL",
                               "MATCHED_MODEL_ONLY", "OTHER_REQUIRED_FIELD_REJECTED")}
    for family, live, epoch, endpoint, comp, app, right in itertools.product(
        (4, 6), (False, True), (False, True), (False, True),
        ("equal", "different", "missing"), (False, True), (False, True)):
        result = outcome(family, live, epoch, endpoint, comp, app, right)
        counts[result] += 1
        rows.append(f"{family}|{int(live)}|{int(epoch)}|{int(endpoint)}|{comp}|{int(app)}|{int(right)}|{result}\n")
    if len(rows) != 192 or counts != {
        "COMPARTMENT_UNBOUND_CONDITIONAL": 4, "MATCHED_MODEL_ONLY": 2,
        "OTHER_REQUIRED_FIELD_REJECTED": 186,
    }:
        raise RuntimeError("MATRIX_INVARIANT_FAILURE:" + str(counts))
    return {"states": len(rows), "categories": counts,
            "sha256": hashlib.sha256("".join(rows).encode("ascii")).hexdigest(),
            "compartment_evidence_proved": False, "native_wfp_executed": False,
            "endpoint_reuse_observed": False, "release_accepted": False}


def main():
    p = argparse.ArgumentParser()
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--source-root", type=Path)
    group.add_argument("--model-only", action="store_true")
    args = p.parse_args()
    if args.source_root is not None:
        source_gate(args.source_root)
    print(json.dumps(run(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
