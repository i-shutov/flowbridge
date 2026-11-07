#!/usr/bin/env python3
"""Independent, offline, dependency-free research audit. No Windows APIs.

This is a separately written specification oracle and source-surface check,
NOT a Rust binary test, WFP intercept test, or independent native acceptance.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def baseline():
    return {
        "source": "kernel", "session": 41, "ticket": 123,
        "pid": 510, "epoch": 133_000_000_000,
        "app": "opaque_A", "selected": "opaque_A",
        "transport": "tcp", "redirect_state": "not_redirected",
        "family": 4, "ip": "192.0.2.10", "port": 443,
        "accepted": {
            "source": "kernel", "session": 41, "ticket": 123,
            "pid": 510, "epoch": 133_000_000_000, "app": "opaque_A",
            "transport": "tcp", "redirect_state": "not_redirected",
            "family": 4, "ip": "192.0.2.10", "port": 443,
        },
        "record": True, "context": True, "own_redirect_handle": True,
        "socket_binding": True, "records_set_before_connect": True,
        "filter": True, "callout": True, "ssh": True,
    }


def decide(d: dict) -> str:
    if not d["filter"] or not d["callout"]:
        return "UNPROTECTED"
    if d["transport"] != "tcp":
        return "UNCOVERED"
    if d["app"] != d["selected"]:
        return "OUTSIDE_SCOPE"
    expected_receipt = {key: d[key] for key in (
        "source", "session", "ticket", "pid", "epoch", "app",
        "transport", "redirect_state", "family", "ip", "port")}
    if (
        d["source"] != "kernel" or d["session"] != 41
        or d["ticket"] == 0 or d["pid"] == 0 or d["epoch"] == 0
        or not d["app"] or d["redirect_state"] != "not_redirected"
        or not d["ip"] or d["ip"] in ("0.0.0.0", "::") or d["port"] == 0
        or d["accepted"] != expected_receipt
        or not all(d[x] for x in (
            "record", "context", "own_redirect_handle", "socket_binding",
            "records_set_before_connect"))
        or not d["ssh"]
    ):
        return "REJECT_INGRESS"
    return "MODEL_ROUTE"


def audit_safety_surface() -> None:
    source = (HERE / "trust_contract.rs").read_text(encoding="utf-8")
    assert "#![forbid(unsafe_code)]" in source
    forbidden = [
        'extern "system"', "unsafe {", "FwpmFilterAdd", "FwpsCalloutRegister",
        "FwpmEngineOpen", "CreateService", "SIO_SET_WFP", "TcpStream::connect",
        "std::process::Command", "LoadLibrary", "SetWindowsHookEx",
    ]
    for token in forbidden:
        assert token not in source, f"unexpected operating-system side effect: {token}"
    required = [
        "missing_record_context_handle_or_socket_binding_rejected",
        "pid_reuse_different_creation_epoch_rejected_even_with_same_tuple",
        "capture_ticket_swapping_rejected_even_if_5tuple_unchanged",
        "same_ticket_replay_rejected_even_if_all_fields_match",
        "no_kernel_filter_or_callout_is_unprotected_not_system_fail_closed",
        "lost_ssh_denies_owned_ingress_only_not_sibling_direct",
        "udp_quic_dns_and_icmp_not_covered_by_tcp_redirect",
        "proxy_loops_other_provider_and_previously_self_are_not_recaptured",
        "capacity_is_bounded_without_replay_permitting_eviction",
    ]
    for token in required:
        assert token in source, f"missing Rust regression name: {token}"
    assert source.count("#[test]") >= 17, "missing negative test coverage"


def main() -> None:
    audit_safety_surface()
    cases = json.loads((HERE / "negative_cases.json").read_text(encoding="utf-8"))
    ok = 0
    outcomes = {}
    for case in cases:
        d = baseline()
        for key, value in case["mutate"].items():
            if key.startswith("accepted."):
                d["accepted"][key.split(".", 1)[1]] = value
            else:
                d[key] = value
        verdict = decide(d)
        assert verdict == case["expected"], (case["case"], verdict, case["expected"])
        outcomes[verdict] = outcomes.get(verdict, 0) + 1
        ok += 1
    assert ok >= 25, "insufficient independent scenario matrix"
    print(json.dumps({
        "ok": True,
        "independent_synthetic_cases": ok,
        "outcomes": outcomes,
        "rust_native_compiled": False,
        "actual_wfp_interception_proved": False,
        "actual_pid_epoch_source_proved": False,
        "system_no_direct_proved": False,
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
