"""WIN-01 source-bound terminal claim regression (not physical kernel G2).

The actual production WDK driver and the elevated user-mode helper must
collaborate to consume one kernel AUTH receipt before Rust creates any
outbound socket. This is an owner-handle claim, NOT independent proof of
the accepted socket object's kernel identity.
"""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATHS = (
    "native/windows/wfp/control.h",
    "native/windows/wfp/driver/driver.c",
    "native/windows/wfp/auth_receipt.h",
    "native/windows/wfp/capture.cpp",
    "native/windows/wfp/capture.h",
    "native/windows/wfp/service.cpp",
)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise AssertionError(code)


def audit(texts: list[str]) -> None:
    control, kernel, ticket, helper, helper_header, service = texts

    require("#define FB_WFP_ABI 4u" in control and
            "#define FB_IOCTL_CLAIM CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_WRITE_DATA)"
            in control and
            "} FbWfpClaim;" in control,
            "old_helper_may_skip_claim_or_claim_abi_missing")
    require("case FB_IOCTL_CLAIM:" in kernel and
            "InputBufferLength != sizeof(FbWfpClaim)" in kernel and
            "FbValidateClaim(received, gOwnerPid, &requested)" in kernel,
            "kernel_claim_not_fixed_size_or_unsupported")
    require("gOwner != stack->FileObject || gOwnerPid != ULongToHandle(IoGetRequestorProcessId(irp))"
            in kernel, "unauthenticated_ioctl_requester")
    require("!gEnabled || !gEpochNotifierRegistered ||" in kernel and
            "gEpochTable.lost || gAuthBook.lost" in kernel,
            "stopped_or_poisoned_kernel_can_claim")
    require("FbEpochLookup(&gEpochTable, requested.pid, &live)" in kernel and
            "live.creation_100ns != requested.creation_100ns" in kernel and
            "live.start_key != requested.process_start_key" in kernel,
            "kernel_claim_lacks_actual_process_incarnation")
    require("FbAuthClaim(&gAuthBook, &requested)" in kernel and
            "status = STATUS_ACCESS_DENIED; break;" in kernel,
            "claim_does_not_consume_OS_AUTH_receipt")
    require("book->slots[i].state != 2" in ticket and
            "book->slots[matchIndex].state = 3;" in ticket and
            "!FbAuthEqual(&book->slots[i].origin, exact)" in ticket,
            "terminal_claim_replay_or_substituted_origin")
    require("void Capture::claim(SOCKET accepted, const FbRedirectContext& context)" in helper and
            "DeviceIoControl(driver_,FB_IOCTL_CLAIM," in helper and
            "throw std::runtime_error(\"WFP kernel claim refused:" in helper,
            "user_mode_can_skip_actual_kernel_ioctl")
    socket_start=helper.find("getsockname(accepted,reinterpret_cast<sockaddr*>(&address),&length)")
    socket_guard=helper.find("v4->sin_addr.s_addr!=htonl(INADDR_LOOPBACK)")
    family_guard=helper.find("context.address_family==AF_INET6")
    claim_call=helper.find("DeviceIoControl(driver_,FB_IOCTL_CLAIM,")
    require(0 <= socket_start < socket_guard < claim_call and
            0 <= family_guard < claim_call and
            "v4->sin_port!=port4be_" in helper and
            "v6->sin6_port!=port6be_" in helper and
            "in6addr_loopback" in helper,
            "accepted_socket_family_loopback_or_broker_port_not_verified")
    require("std::lock_guard<std::mutex> lock(ownerMutex_);" in helper and
            "std::mutex ownerMutex_" in helper_header,
            "Stop_and_claim_driver_handle_race")
    begin = service.find("void handle(SOCKET raw")
    query = service.find("fb_wfp_query(raw,&context,records.data()", begin)
    stop_check = service.find("if(stopping) throw std::runtime_error(", query)
    claim = service.find("capture.claim(raw,context);", query)
    connect = service.find("fb_native_stream_open_wfp_json(", query)
    require(0 <= begin < query < stop_check < claim < connect,
            "claim_not_between_real_OS_WSAIoctl_and_Rust_outbound_socket")
    require("handle(socket,native.id,idleMs,capture)" in service,
            "worker_not_using_exclusive_live_capture_owner")
    require("if (!DeviceIoControl(driver_,FB_IOCTL_CLAIM," in helper,
            "claim_ioctl_result_ignored")
    # No accepted-socket object proof is invented in API names/status.
    require("not independent kernel socket identity" in
            (control + helper + helper_header + service).lower() or
            "not independent socket attestation" in
            (control + helper + helper_header + service).lower(),
            "missing_trust_boundary_disclosure")


class TerminalClaimSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.files = [(ROOT / path).read_text(encoding="utf-8") for path in PATHS]

    def test_exact_production_source_includes_terminal_claim(self) -> None:
        audit(self.files)

    def test_eleven_adversarial_source_mutants_are_rejected(self) -> None:
        mutations = [
            (0, "#define FB_WFP_ABI 4u", "#define FB_WFP_ABI 3u"),
            (1, "case FB_IOCTL_CLAIM:", "case FB_IOCTL_RETIRED:"),
            (1, "FbEpochLookup(&gEpochTable, requested.pid, &live)",
             "FakePidOnlySnapshot(&gEpochTable, requested.pid, &live)"),
            (1, "FbAuthClaim(&gAuthBook, &requested)", "1 /* trust user input */"),
            (2, "book->slots[i].state != 2", "book->slots[i].state != 1"),
            (2, "book->slots[matchIndex].state = 3;", "book->slots[matchIndex].state = 2;"),
            (3, "DeviceIoControl(driver_,FB_IOCTL_CLAIM,", "DeviceIoControl(driver_,FB_IOCTL_QUERY,"),
            (5, "capture.claim(raw,context);", "// omitted terminal claim"),
            (5, "fb_native_stream_open_wfp_json(", "fb_native_stream_open_without_claim_json("),
            (3, "getsockname(accepted,reinterpret_cast<sockaddr*>(&address),&length)",
             "FakeUnverifiedSocketName(accepted,&address,&length)"),
            (3, "v4->sin_port!=port4be_", "false /* allow foreign broker port */"),
        ]
        for index, before, after in mutations:
            original = self.files[index]
            self.assertEqual(original.count(before), 1,
                             "mutation target missing/ambiguous: " + before[:60])
            altered = list(self.files)
            altered[index] = original.replace(before, after)
            with self.subTest(fault=before[:48]):
                with self.assertRaises(AssertionError):
                    audit(altered)


if __name__ == "__main__":
    unittest.main()
