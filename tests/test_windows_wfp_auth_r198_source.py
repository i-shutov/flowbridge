"""Source-bound negative acceptance for dual-stack WFP AUTH and R198 AppId collision.

Tests are NOT an installed kernel callout, signed WFP/native G2 or packet
egress acceptance. The separate MSVC suite compiles production C receipts.
"""
from __future__ import annotations
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "native/windows/wfp/capture.cpp"
DRIVER = ROOT / "native/windows/wfp/driver/driver.c"
TICKETS = ROOT / "native/windows/wfp/auth_receipt.h"
GUIDS = ROOT / "native/windows/wfp/control.h"


def require(check: bool, code: str) -> None:
    if not check:
        raise AssertionError(code)


def check_source(policy: str, driver: str, tickets: str, guids: str) -> None:
    # A selected external SSH connection may retain ORIGINAL_APP_ID=selected,
    # but its CURRENT OS app is the broker. Filter only on the current selected
    # application identity; do not add a conditional broker PID exemption.
    require("FWPM_LAYER_ALE_AUTH_CONNECT_V4" in policy and
            "FWPM_LAYER_ALE_AUTH_CONNECT_V6" in policy, "dual_stack_AUTH_not_installed")
    require("FB_WFP_AUTH_CALLOUT4" in guids and "FB_WFP_AUTH_CALLOUT6" in guids,
            "AUTH_GUIDS_missing")
    require("const GUID authLayers[]" in policy and
            "const GUID authKeys[]" in policy and
            'filter.action.type=FWP_ACTION_CALLOUT_TERMINATING;' in policy,
            "AUTH_not_terminating")
    require("FWPM_CONDITION_ALE_ORIGINAL_APP_ID" not in policy and
            "auto conditions=selected.tcpConditions();" in policy and
            "condition.fieldKey=FWPM_CONDITION_ALE_APP_ID;" in policy,
            "R198_proxy_original_AppId_self_block")
    require("selected.sameOsIdentity(excluded)" in policy and
            "Selected application overlaps protected transport bypass" in policy,
            "selected_AppId_bypass_collision")
    require(policy.index("selected.sameOsIdentity(excluded)") <
            policy.index("driver_=CreateFileW(FB_WFP_DEVICE"),
            "bypass_overlap_checked_after_driver_access")
    require("static void NTAPI FbAuthClassify" in driver and
            "callout.classifyFn = FbAuthClassify;" in driver and
            "FwpsCalloutRegister1(gDevice, &callout, &gAuthCallout4)" in driver and
            "FwpsCalloutRegister1(gDevice, &callout, &gAuthCallout6)" in driver,
            "AUTH_callbacks_not_registered")
    require("FWPS_METADATA_FIELD_ORIGINAL_DESTINATION" in driver and
            "FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID" in driver and
            "FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE" in driver and
            "FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED" in driver and
            "FWP_CONDITION_FLAG_IS_REAUTHORIZE" in driver,
            "real_original_WFP_metadata_missing")
    require("FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID" in driver and
            "FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID" in driver and
            "FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_ORIGINAL_APP_ID" not in driver,
            "current_OS_app_identity_lost")
    require("RtlUshortByteSwap(v4 ? config.port_v4_be : config.port_v6_be)" in driver,
            "host_network_port_order_confused")
    require("RtlCompareMemory(ip->byteArray16, loopback" in driver and
            "values->incomingValue[ipIndex].value.uint32 != 0x7f000001" in driver,
            "external_SSH_accepted_as_loopback")
    require("FbAuthIssue(&gAuthBook, &item)" in driver and
            driver.count("FbIssueOriginalReceipt(context, ownerPid, &stagedReceipt)") == 2 and
            "FbAuthRetire(&gAuthBook, &stagedReceipt)" in driver,
            "same_kernel_redirect_did_not_issue_and_retire")
    require("FbAuthConsumeObserved(&gAuthBook, &observed)" in driver and
            "FbEpochLookup(&gEpochTable, observed.pid, &process)" in driver,
            "AUTH_missing_native_PID_epoch_link")
    require("if (out->actionType == FWP_ACTION_PERMIT) FbBlock(out);" in driver and
            "if (!approved) { FbBlock(out); return; }" in driver,
            "hard_PERMIT_veto_or_default_deny_removed")
    require("FbAuthProcessExit(&gAuthBook" in driver and
            "gAuthBook.lost = 1" in driver,
            "process_death_or_driver_stop_does_not_revoke_AUTH")
    require("if (!book || book->lost || !FbAuthOriginValid(item))" in tickets and
            "book->slots[matchIndex].state = 2" in tickets and
            "book->lost = 1" in tickets,
            "one_shot_or_overflow_protection_missing")


class R198SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = [p.read_text(encoding="utf-8") for p in
                    [POLICY, DRIVER, TICKETS, GUIDS]]

    def test_product_source_contract_conservative(self) -> None:
        check_source(*self.data)

    def test_eight_independent_bypass_mutations_rejected(self) -> None:
        cases = [
            (0, "auto conditions=selected.tcpConditions();",
             "auto conditions=maybeOriginalAppId();"),
            (0, "selected.sameOsIdentity(excluded)",
             "false /* allow selected bypass collision */"),
            (0, "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
             "FWPM_LAYER_ALE_CONNECT_REDIRECT_V6"),
            (1, "values->incomingValue[ipIndex].value.uint32 != 0x7f000001",
             "values->incomingValue[ipIndex].value.uint32 != 0xffffffff"),
            (1, "if (out->actionType == FWP_ACTION_PERMIT) FbBlock(out);",
             "if (out->actionType == FWP_ACTION_PERMIT) return;"),
            (1, "FbAuthConsumeObserved(&gAuthBook, &observed)",
             "1 /* PID-only broker bypass */"),
            (1, "RtlUshortByteSwap(v4 ? config.port_v4_be : config.port_v6_be)",
             "(v4 ? config.port_v4_be : config.port_v6_be)"),
            (2, "book->slots[matchIndex].state = 2",
             "book->slots[matchIndex].state = 1"),
        ]
        for which, before, after in cases:
            state = list(self.data)
            self.assertEqual(state[which].count(before), 1, before[:55])
            state[which] = state[which].replace(before, after)
            with self.subTest(removed=before[:50]):
                with self.assertRaises(AssertionError):
                    check_source(*state)


if __name__ == "__main__":
    unittest.main()
