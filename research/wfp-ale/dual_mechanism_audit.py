#!/usr/bin/env python3
"""Offline comparison: WFP conditional authority vs NDISRD no per-frame owner.

No OS/WFP calls, network, drivers, filters or external dependencies.
"""
from dataclasses import dataclass, replace
from itertools import product
import json

@dataclass(frozen=True)
class Evidence:
    backend: str = "wfp"
    family: int = 4
    transport: str = "tcp"
    app_id: str = "A"
    selected_app_id: str = "A"
    pid: int = 510
    epoch: int = 140000
    classify_source: str = "kernel"
    fixed_app_id: bool = True
    metadata_pid: bool = True
    referenced_same_process: bool = True
    canonical_image_verified: bool = True
    context_from_accepted_socket: bool = True
    records_from_accepted_socket: bool = True
    outbound_records_before_connect: bool = True
    ticket: int = 1
    accepted_ticket: int = 1
    session: int = 7
    accepted_session: int = 7
    process_alive: bool = True
    ssh_ready: bool = True
    filter_active: bool = True
    callout_active: bool = True
    tuple_match: bool = True

def decide(e: Evidence) -> str:
    if e.backend == "ndisrd":
        return "NO_PER_FRAME_OWNER_PROOF"
    if e.backend != "wfp":
        return "UNSUPPORTED_BACKEND"
    if not e.filter_active or not e.callout_active:
        return "NOT_SYSTEM_PROTECTED"
    if e.transport != "tcp" or e.family not in (4, 6):
        return "TRANSPORT_UNCOVERED"
    if e.app_id != e.selected_app_id:
        return "NOT_SELECTED"
    if (
        e.classify_source != "kernel" or e.pid == 0 or e.epoch == 0
        or not e.fixed_app_id or not e.metadata_pid
        or not e.referenced_same_process or not e.canonical_image_verified
        or not e.context_from_accepted_socket
        or not e.records_from_accepted_socket
        or not e.outbound_records_before_connect
        or e.session == 0 or e.session != e.accepted_session
        or e.ticket == 0 or e.ticket != e.accepted_ticket
        or not e.process_alive or not e.ssh_ready
    ):
        return "REJECT_OWNED_INGRESS"
    return "CONDITIONAL_MODEL_ONLY"

def main() -> None:
    base = Evidence()
    assert decide(base) == "CONDITIONAL_MODEL_ONLY"
    counts = {}
    checks = 0
    def check(e: Evidence, expected: str) -> None:
        nonlocal checks
        actual = decide(e)
        assert actual == expected, (e, actual, expected)
        counts[actual] = counts.get(actual, 0) + 1
        checks += 1

    for family, tuple_match, alive, epoch_ok, context_ok, ssh_ready in product(
        (4, 6), repeat=6
    ):
        # Binary product axes are encoded as ints 4/6 to avoid false truth.
        family = 4 if family == 4 else 6
        a = replace(base, family=family, tuple_match=tuple_match == 6,
                    process_alive=alive == 6,
                    referenced_same_process=epoch_ok == 6,
                    context_from_accepted_socket=context_ok == 6,
                    ssh_ready=ssh_ready == 6)
        expected = ("CONDITIONAL_MODEL_ONLY"
                    if alive == 6 and epoch_ok == 6 and context_ok == 6 and ssh_ready == 6
                    else "REJECT_OWNED_INGRESS")
        check(a, expected)
        check(replace(a, backend="ndisrd"), "NO_PER_FRAME_OWNER_PROOF")

    for field, value, expected in [
        ("classify_source", "etw", "REJECT_OWNED_INGRESS"),
        ("classify_source", "iphelper", "REJECT_OWNED_INGRESS"),
        ("fixed_app_id", False, "REJECT_OWNED_INGRESS"),
        ("metadata_pid", False, "REJECT_OWNED_INGRESS"),
        ("canonical_image_verified", False, "REJECT_OWNED_INGRESS"),
        ("records_from_accepted_socket", False, "REJECT_OWNED_INGRESS"),
        ("outbound_records_before_connect", False, "REJECT_OWNED_INGRESS"),
        ("accepted_ticket", 2, "REJECT_OWNED_INGRESS"),
        ("accepted_session", 8, "REJECT_OWNED_INGRESS"),
        ("pid", 0, "REJECT_OWNED_INGRESS"),
        ("epoch", 0, "REJECT_OWNED_INGRESS"),
        ("ticket", 0, "REJECT_OWNED_INGRESS"),
        ("filter_active", False, "NOT_SYSTEM_PROTECTED"),
        ("callout_active", False, "NOT_SYSTEM_PROTECTED"),
        ("app_id", "sibling", "NOT_SELECTED"),
        ("transport", "udp", "TRANSPORT_UNCOVERED"),
        ("transport", "icmp", "TRANSPORT_UNCOVERED"),
        ("backend", "other", "UNSUPPORTED_BACKEND"),
    ]:
        check(replace(base, **{field: value}), expected)

    print(json.dumps({
        "passed": checks, "by_verdict": counts,
        "rust_compiled": False, "real_kernel_witness": False,
        "physical_no_direct": False, "driver_executed": False
    }, sort_keys=True))

if __name__ == "__main__":
    main()
