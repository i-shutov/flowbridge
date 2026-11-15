#!/usr/bin/env python3
"""Source-level guard for native WFP epoch v3, NEVER a loaded-driver G2 proof."""
from __future__ import annotations
from pathlib import Path
import json
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "native/windows/wfp/driver/driver.c"
CONTEXT = ROOT / "native/windows/wfp/redirect_context.h"
READER = ROOT / "native/windows/wfp/redirect_io.cpp"
CONTROL = ROOT / "native/windows/wfp/control.h"
TABLE = ROOT / "native/windows/wfp/process_epoch.h"
FFI = ROOT / "crates/flowbridge-ffi/src/lib.rs"


def require(ok: bool, why: str) -> None:
    if not ok:
        raise AssertionError(why)


def audit(driver: str, context: str, reader: str, control: str, table: str) -> None:
    require("#define FB_WFP_ABI 3u" in control, "legacy driver ABI still allowed")
    require("#define FB_REDIRECT_VERSION 3u" in context and
            "#define FB_REDIRECT_CONTEXT_BYTES 2136u" in context,
            "legacy context layout accepted")
    for field in ("original_process_creation_100ns",
                  "original_process_start_key", "original_transport_endpoint"):
        require(field in context and field in reader and field in driver,
                "missing end-to-end kernel context field: " + field)
    require("!candidate.original_process_creation_100ns" in reader and
            "!candidate.original_process_start_key" in reader and
            "!candidate.original_transport_endpoint" in reader,
            "accepted-socket consumer treats missing origin as valid")
    require("PsSetCreateProcessNotifyRoutineEx(FbProcessNotify, FALSE)" in driver and
            "PsSetCreateProcessNotifyRoutineEx(FbProcessNotify, TRUE)" in driver and
            "PsGetProcessCreateTimeQuadPart(process)" in driver and
            "PsGetProcessStartKey(process)" in driver and
            "FbEpochInsert(&gEpochTable, record)" in driver and
            "FbEpochExit(&gEpochTable, record)" in driver,
            "kernel process lifecycle witness incomplete")
    require("KeAcquireSpinLock(&gLock, &irql)" in driver and
            "FbEpochLookup(&gEpochTable, metadata->processId, &processEpoch)" in driver,
            "source PID promoted without a locked native birth-epoch table")
    require("if (!enabled || epochLost) { FbBlock(out); return; }" in driver,
            "disabled WFP backend releases a selected flow DIRECT")
    require("state != FWPS_CONNECTION_NOT_REDIRECTED) { FbBlock(out); return; }" in driver,
            "foreign redirector releases a selected flow DIRECT")
    require("if (request->previousVersion && request->previousVersion->localRedirectHandle)" in driver and
            re.search(r"if \(request->previousVersion && request->previousVersion->localRedirectHandle\)\s*\{"
                      r"[^{}]*FbBlock\(out\);", driver) is not None,
            "other provider's previous WFP redirect was permitted")
    require("FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE" in driver and
            "metadata->transportEndpointHandle == 0) { FbBlock(out); return; }" in driver,
            "transport endpoint handle missing but selected connection admitted")
    require("if (gEpochTable.lost || !gEpochNotifierRegistered)" in driver and
            "status = STATUS_DEVICE_NOT_READY" in driver,
            "driver config allowed after process ledger loss")
    require("if (firstFree == FB_EPOCH_CAPACITY)" in table and
            "table->lost = 1" in table and
            "table->entries[firstFree] = record" in table and
            "current->process_token != record.process_token" in table,
            "process birth collision, overflow or exit mismatch could admit an old PID")
    require("if (!table || !out || !pid || table->lost) return 0;" in table,
            "lost process ledger remains usable")


class G2SourceSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.files = [p.read_text(encoding="utf-8") for p in
                     (DRIVER, CONTEXT, READER, CONTROL, TABLE)]

    def test_true_source_sealed_not_native_accepted(self) -> None:
        audit(*self.files)

    def test_wfp_redirect_records_cannot_select_direct_in_rust_ffi(self) -> None:
        ffi = FFI.read_text(encoding="utf-8")
        self.audit_ffi_guard(ffi)

    @staticmethod
    def audit_ffi_guard(ffi: str) -> None:
        # Must be reached synchronously before any stream lease or TCP socket.
        start = ffi.index("fn open_stream_managed(")
        route = ffi.index("let route = config.route(&decision.action)", start)
        guard = ffi.find(
            "require_wfp_upstream(&decision.action, route.len(), redirect_records.is_some())?;",
            route,
        )
        lease = ffi.index("let lease = StreamLease::reserve()?", route)
        require(route < guard < lease, "WFP DIRECT guard is absent or too late")
        require("Action::Proxy { .. } | Action::Chain { .. } if route_hops > 0 => Ok(())"
                in ffi, "WFP proxy route was not required")
        require("if !with_records {" in ffi and
                "DIRECT is forbidden" in ffi,
                "WFP redirection can return to DIRECT")

    def test_two_wfp_direct_guard_mutations_rejected(self) -> None:
        ffi = FFI.read_text(encoding="utf-8")
        guard = "require_wfp_upstream(&decision.action, route.len(), redirect_records.is_some())?;"
        deny = "Action::Proxy { .. } | Action::Chain { .. } if route_hops > 0 => Ok(())"
        self.assertEqual(ffi.count(guard), 1)
        self.assertEqual(ffi.count(deny), 1)
        for before, after in [
            (guard, "/* previously guarded flow */"),
            (deny, "Action::Direct => Ok(())"),
        ]:
            with self.subTest(before=before[:40]):
                with self.assertRaises(AssertionError):
                    self.audit_ffi_guard(ffi.replace(before, after))

    def test_seven_reintroduced_faults_are_rejected(self) -> None:
        driver, context, reader, control, table = self.files
        mutants = [
            (0, "if (!enabled || epochLost) { FbBlock(out); return; }",
             "if (!enabled || epochLost) { return; }"),
            (0, "state != FWPS_CONNECTION_NOT_REDIRECTED) { FbBlock(out); return; }",
             "state != FWPS_CONNECTION_NOT_REDIRECTED) { return; }"),
            (0, "FbEpochLookup(&gEpochTable, metadata->processId, &processEpoch)",
             "FakePidOnlyLookup(&gEpochTable, metadata->processId, &processEpoch)"),
            (0, "if (gEpochTable.lost || !gEpochNotifierRegistered)",
             "if (!gEpochNotifierRegistered)"),
            (2, "!candidate.original_process_creation_100ns",
             "candidate.original_process_creation_100ns"),
            (1, "#define FB_REDIRECT_VERSION 3u", "#define FB_REDIRECT_VERSION 2u"),
            (4, "if (!table || !out || !pid || table->lost) return 0;",
             "if (!table || !out || !pid) return 0;"),
        ]
        for index, before, after in mutants:
            source = list(self.files)
            self.assertEqual(source[index].count(before), 1,
                             "mutation anchor ambiguous or missing")
            source[index] = source[index].replace(before, after)
            with self.subTest(index=index, fault=before[:55]):
                with self.assertRaises(AssertionError):
                    audit(*source)


if __name__ == "__main__":
    unittest.main()
