#!/usr/bin/env python3
"""Pure-stdlib, offline negative model for WFP ALE process-epoch provenance.

This script performs no Win32/WFP/API calls. MODEL_CANDIDATE is not OS proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class Entry:
    pid: int
    object_tag: str
    epoch: int
    app_id: str
    exact_image: bool
    referenced: bool
    version: int


class Ledger:
    def __init__(self):
        self.live: dict[int, Entry] = {}
        self.poisoned: set[int] = set()
        self.version = 0

    def event(self, op):
        action = op["action"]
        pid = op.get("pid", 510)
        if action == "create":
            if pid in self.live:
                self.poisoned.add(pid)  # overlapping generation: cannot attest
            self.version += 1
            self.live[pid] = Entry(pid, op.get("object", "object-A"),
                                   op.get("epoch", 133000000000),
                                   op.get("app", "app-A"),
                                   op.get("exact_image", True),
                                   op.get("referenced", True), self.version)
        elif action == "exit":
            actual = self.live.get(pid)
            if actual is None or actual.object_tag != op.get("object", "object-A"):
                self.poisoned.add(pid)  # out-of-order or unknown exit
            else:
                self.live.pop(pid)
            self.version += 1
        elif action == "missed_callback":
            self.live.pop(pid, None)
            self.poisoned.add(pid)
            self.version += 1
        else:
            raise ValueError(f"unknown event: {action}")


def verdict(ledger: Ledger, probe: dict, after_ops: list[dict]) -> str:
    """Snapshot at classify; process events may happen before PASSIVE worker."""
    pid = probe.get("pid", 510)
    layer = probe.get("layer", "ALE_CONNECT_REDIRECT_V4")
    if layer not in ("ALE_CONNECT_REDIRECT_V4", "ALE_CONNECT_REDIRECT_V6"):
        return "WRONG_LAYER"
    if not probe.get("metadata_pid", True) or not probe.get("metadata_path", True):
        return "MISSING_WFP_METADATA"
    if probe.get("app", "app-A") != probe.get("selected_app", "app-A"):
        return "OUTSIDE_SELECTED_APP"
    snapshot = ledger.live.get(pid)
    if pid in ledger.poisoned or snapshot is None:
        return "NO_VALID_PROCESS_CALLBACK"
    if (not snapshot.referenced or not snapshot.exact_image or not snapshot.object_tag
            or snapshot.epoch <= 0 or snapshot.app_id != probe.get("app", "app-A")):
        return "INCOMPLETE_PROCESS_RECORD"

    irql = probe.get("irql", "PASSIVE")
    strategy = probe.get("strategy", "inline_lookup")
    if strategy == "pend_operation":
        # FwpsPendOperation0 is not the async redirect primitive.
        return "INVALID_PEND_OPERATION_LAYER"
    if irql not in ("PASSIVE", "APC", "DISPATCH"):
        return "INVALID_IRQL"
    if irql == "DISPATCH" and strategy == "inline_lookup":
        # PsLookupProcessByProcessId is pageable and needs <= APC_LEVEL.
        return "ILLEGAL_PAGEABLE_LOOKUP"
    if irql == "DISPATCH" and strategy != "pend_classify":
        return "INVALID_DEFER_STRATEGY"
    if strategy == "pend_classify":
        if probe.get("pend_status", "success") != "success":
            return "PEND_CLASSIFY_NOT_GRANTED"
        if probe.get("worker_irql", "PASSIVE") not in ("PASSIVE", "APC"):
            return "ILLEGAL_WORKER_IRQL"
        if probe.get("timeout", False):
            return "PEND_EXPIRED"
    elif strategy != "inline_lookup":
        return "INVALID_DEFER_STRATEGY"

    # The ledger's subsequent notifications cannot be ignored even when PID
    # and application path look identical; an EPROCESS pointer is not a PID.
    for op in after_ops:
        ledger.event(op)
    live = ledger.live.get(pid)
    if pid in ledger.poisoned or live != snapshot:
        return "PROCESS_GENERATION_CHANGED"
    if not probe.get("lookup_ref_held", True):
        return "UNREFERENCED_PROCESS_OBJECT"
    if (probe.get("lookup_object", "object-A") != snapshot.object_tag
            or probe.get("lookup_epoch", 133000000000) != snapshot.epoch):
        return "LOOKUP_OBJECT_OR_EPOCH_MISMATCH"
    return "MODEL_CANDIDATE_ONLY"


def run_case(case: dict) -> str:
    ledger = Ledger()
    for op in case.get("before", [{"action": "create"}]):
        ledger.event(op)
    return verdict(ledger, case.get("probe", {}), case.get("after", []))


def static_surface_check() -> None:
    # These are safety guardrails, not a substitute for review or compilation.
    src = (Path(__file__).resolve().parent / "appid_readonly.rs").read_text(encoding="utf-8")
    for exact in ("FwpmGetAppIdFromFileName0", "FwpmFreeMemory0", "Fwpuclnt"):
        assert exact in src, exact
    for forbidden in ("FwpmEngineOpen", "FwpmFilterAdd", "FwpsCalloutRegister",
                      "FwpsPendClassify", "CreateService", "NDISRD", "TcpStream",
                      "std::process::Command", "WinDivert", "SetWindowsHookEx"):
        assert forbidden not in src, forbidden


def main() -> None:
    static_surface_check()
    path = Path(__file__).resolve().parent / "epoch_cases.json"
    cases = json.loads(path.read_text(encoding="utf-8"))
    assert len(cases) >= 25
    count: dict[str, int] = {}
    for case in cases:
        got = run_case(case)
        expected = case["expect"]
        assert got == expected, (case["name"], got, expected)
        count[got] = count.get(got, 0) + 1
    # Independent safety properties derived from API preconditions; not a
    # second execution of the same state-machine implementation.
    assert run_case({"probe": {"irql": "DISPATCH"}}) == "ILLEGAL_PAGEABLE_LOOKUP"
    assert run_case({"probe": {"irql": "DISPATCH", "strategy": "pend_operation"}}) == "INVALID_PEND_OPERATION_LAYER"
    assert run_case({"probe": {"irql": "DISPATCH", "strategy": "pend_classify"}}) == "MODEL_CANDIDATE_ONLY"
    assert run_case({"after": [{"action": "exit"}, {"action": "create", "object": "object-B", "epoch": 134000000000}]}) != "MODEL_CANDIDATE_ONLY"
    assert run_case({"probe": {"app": "app-B", "selected_app": "app-A"}}) == "OUTSIDE_SELECTED_APP"
    print(json.dumps({"synthetic_cases_passed": len(cases), "by_verdict": count,
                      "real_WFP_calls": 0, "kernel_epoch_attribution_proved": False,
                      "process_callback_registered": False,
                      "windows_appid_probe_executed": False,
                      "system_fail_closed_proved": False}, sort_keys=True))


if __name__ == "__main__":
    main()
