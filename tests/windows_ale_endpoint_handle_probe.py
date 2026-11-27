"""Observe the transport endpoint handles of two owned Win11 loopback sockets."""

import ctypes
import json
import os
import socket
import sys
from contextlib import ExitStack


# Windows SDK mstcpip.h: _WSAIOR(IOC_VENDOR, 205).
# https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/constant.SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE.html
SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE = 0x580000CD
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800
IMAGE_FILE_MACHINE_AMD64 = 0x8664
EXPECTED_HOST = "VM-326272"
SOCKET_TIMEOUT = 3
DWORD = ctypes.c_uint32
ENDPOINT_HANDLE = ctypes.c_uint64


class ProbeFailure(Exception):
    pass


def require_expected_win11():
    if (
        sys.platform != "win32"
        or ctypes.sizeof(ctypes.c_void_p) != 8
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_REPOSITORY") != "i-shutov/flowbridge"
        or os.environ.get("RUNNER_ENVIRONMENT") != "self-hosted"
        or os.environ.get("RUNNER_NAME") != "win11-flowbridge"
    ):
        raise ProbeFailure("runner_guard")

    version = sys.getwindowsversion()
    if (
        version.product_type != 1
        or version.build < 22000
        or socket.gethostname().casefold() != EXPECTED_HOST.casefold()
    ):
        raise ProbeFailure("runner_guard")

    kernel32 = ctypes.WinDLL("kernel32.dll", winmode=LOAD_LIBRARY_SEARCH_SYSTEM32)
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.IsWow64Process2.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint16),
    )
    kernel32.IsWow64Process2.restype = ctypes.c_int
    process_machine = ctypes.c_uint16()
    native_machine = ctypes.c_uint16()
    if (
        not kernel32.IsWow64Process2(
            kernel32.GetCurrentProcess(),
            ctypes.byref(process_machine),
            ctypes.byref(native_machine),
        )
        or process_machine.value != 0
        or native_machine.value != IMAGE_FILE_MACHINE_AMD64
    ):
        raise ProbeFailure("runner_guard")


def load_ioctl():
    winsock = ctypes.WinDLL("ws2_32.dll", winmode=LOAD_LIBRARY_SEARCH_SYSTEM32)
    ioctl = winsock.WSAIoctl
    ioctl.argtypes = (
        ctypes.c_size_t,
        DWORD,
        ctypes.c_void_p,
        DWORD,
        ctypes.c_void_p,
        DWORD,
        ctypes.POINTER(DWORD),
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    ioctl.restype = ctypes.c_int
    return ioctl


def query_endpoint(ioctl, connection):
    handle = ENDPOINT_HANDLE()
    length = DWORD()
    result = ioctl(
        connection.fileno(),
        SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE,
        None,
        0,
        ctypes.byref(handle),
        ctypes.sizeof(handle),
        ctypes.byref(length),
        None,
        None,
    )
    if result != 0:
        raise ProbeFailure("ioctl_failed")
    return length.value, handle.value


def observe_endpoints(query, connections, report):
    observations = []
    for connection in (*connections, *connections):
        observations.append(query(connection))
        report["queries_completed"] += 1

    report["returned_length_valid"] = all(
        length == ctypes.sizeof(ENDPOINT_HANDLE) for length, _ in observations
    )
    if not report["returned_length_valid"]:
        raise ProbeFailure("unexpected_return_length")

    first, second, repeated_first, repeated_second = (
        handle for _, handle in observations
    )
    report["all_nonzero"] = all((first, second, repeated_first, repeated_second))
    if not report["all_nonzero"]:
        raise ProbeFailure("zero_endpoint_handle")

    report["stable_per_socket"] = (first, second) == (repeated_first, repeated_second)
    if not report["stable_per_socket"]:
        raise ProbeFailure("unstable_endpoint_handle")

    report["distinct_between_sockets"] = first != second
    if not report["distinct_between_sockets"]:
        raise ProbeFailure("duplicate_endpoint_handle")


def observe_loopback(query, report):
    resources = ExitStack()
    try:
        listener = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        listener.settimeout(SOCKET_TIMEOUT)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        address = listener.getsockname()

        connections = []
        for _ in range(2):
            client = resources.enter_context(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            )
            client.settimeout(SOCKET_TIMEOUT)
            client.connect(address)

            connection, peer = listener.accept()
            resources.enter_context(connection)
            if peer != client.getsockname() or connection.getsockname() != address:
                raise ProbeFailure("unexpected_loopback_peer")

            connections.append(connection)
            report["accepted_connections"] += 1

        observe_endpoints(query, connections, report)
    except OSError:
        raise ProbeFailure("loopback_socket_failed") from None
    finally:
        try:
            resources.close()
        except OSError:
            pass
        else:
            report["owned_sockets_closed"] = True

    if not report["owned_sockets_closed"]:
        raise ProbeFailure("socket_cleanup_failed")


def main():
    report = {
        "status": "FAIL",
        "reason": "unexpected_probe_error",
        "accepted_connections": 0,
        "queries_completed": 0,
        "returned_length_valid": False,
        "all_nonzero": False,
        "stable_per_socket": False,
        "distinct_between_sockets": False,
        "owned_sockets_closed": False,
        "g2_accepted": False,
        "packet_owner_bound": False,
        "origin_process_bound": False,
    }
    try:
        require_expected_win11()
        ioctl = load_ioctl()
        observe_loopback(lambda connection: query_endpoint(ioctl, connection), report)
    except ProbeFailure as failure:
        report["reason"] = str(failure)
    except Exception:
        pass
    else:
        report["status"] = "PASS"
        report["reason"] = "owned_socket_endpoint_handles_observed"

    print(json.dumps(report, sort_keys=True))
    return int(report["status"] != "PASS")


if __name__ == "__main__":
    sys.exit(main())
