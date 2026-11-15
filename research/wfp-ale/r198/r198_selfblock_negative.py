#!/usr/bin/env python3
"""R198: conditional source-bound negative test. No WFP, sockets or driver."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
SEL, BROKER = "selected.exe", "broker.exe"

def oracle(original, loopback, redirect_metadata, selected_pid, one_shot):
    if original != SEL:
        return "UNCLASSIFIED"  # Other filters unknown; never equivalent to PERMIT.
    return "MODEL_PERMIT" if (loopback and redirect_metadata and selected_pid and one_shot) else "BLOCK"

def source_checks():
    p = (ROOT / "kernel-r19/policy_windows.rs").read_text()
    a = (ROOT / "kernel-r19/kernel/src/redirect.rs").read_text()
    b = (ROOT / "kernel-r19/broker_windows.rs").read_text()
    cond = p.split("fn conditions(", 1)[1].split("fn filter(", 1)[0]
    auth = a.split("pub unsafe fn auth_classify(", 1)[1]
    ssh = b.split("pub fn claim_and_connect_trusted_ssh(", 1)[1].split("impl TrustedSshRelay", 1)[0]
    guards = [
        "Kind::AttestOriginal{FWPM_CONDITION_ALE_ORIGINAL_APP_ID}" in cond,
        "tcp.conditionValue.Anonymous.uint8=6" in cond,
        0 <= ssh.find("SET_RECORDS") < ssh.find("connect(s.0"),
        "ip:remote.ip().octets()" in ssh,
        "if !loopback{return false;}" in auth,
        "if !auth_check(values,meta){block(out);return;}" in auth,
        "lookup(m.processId)" in auth,
    ]
    assert all(guards), guards
    print("SOURCE 7/7 (structural only)")

cases = [
    ("selected_sibling_direct", SEL, False, False, True, False, "BLOCK"),
    ("original_selected_loopback_candidate", SEL, True, True, True, True, "MODEL_PERMIT"),
    ("tagged_ssh_broker_pid", SEL, False, True, False, False, "BLOCK"),
    ("tagged_ssh_even_with_selected_pid", SEL, False, True, True, True, "BLOCK"),
    ("broker_without_selected_original", BROKER, False, False, False, False, "UNCLASSIFIED"),
    ("ipv6_selected_original_tagged_ipv4_ssh", SEL, False, True, False, False, "BLOCK"),
]
if __name__ == "__main__":
    model_only = sys.argv[1:] == ["--model-only"]
    if not model_only: source_checks()
    for name, original, loopback, metadata, pid, ticket, want in cases:
        got = oracle(original, loopback, metadata, pid, ticket)
        assert got == want, (name, got, want)
        print(name, got)
    print("MODEL 6/6; conditional, NOT native WFP proof; model_only=", model_only)
