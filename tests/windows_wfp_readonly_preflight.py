#!/usr/bin/env python3
"""Actual Windows BFE filter enumeration + live cross-process TCP safety boundary.

READ ONLY: original Rust queries BFE via FwpmEngineOpen0/FilterEnum0,
while an independent OS TCP socket remains connected. No rule/device changes;
neither observation proves packet->PID, WFP/NDISRD ordering, or fail-closed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading

DENIED = (
    "filter_policy_modified", "driver_mode_modified",
    "native_packet_pid_bound", "arbitrary_selected_app_accepted",
    "crash_persistent_fail_closed", "wfp_ndisrd_ordering_proved",
    "dns_leak_free", "win10_11_acceptance", "release_accepted",
)


def snapshot(agent):
    process = subprocess.run(
        [str(agent), "wfp-readonly"], capture_output=True, text=True,
        encoding="utf-8", timeout=15, check=False,
    )
    report = json.loads(process.stdout)
    if process.returncode != 0 or report.get("ok") is not True:
        raise AssertionError("Actual Windows BFE read-only enumeration unavailable")
    if report.get("read_only") is not True or report.get("engine_opened") is not True:
        raise AssertionError("Windows WFP engine was not opened by original Rust")
    if report.get("enumeration_completed") is not True:
        raise AssertionError("Actual Rust WFP filter enumeration not complete")
    if any(report.get(key) is not False for key in DENIED):
        raise AssertionError("Read-only WFP inventory asserted a false protection claim")
    count = report.get("filter_sample_count")
    if type(count) is not int or not 0 <= count <= 8192:
        raise AssertionError("WFP inventory has invalid bounded count")
    if type(report.get("sample_complete")) is not bool:
        raise AssertionError("WFP enumeration completeness was not reported")
    if any(key in report for key in (
        "pid", "process_path", "remote", "local", "packet",
        "filter_names", "filter_ids", "provider_guids", "addresses",
    )):
        raise AssertionError("WFP inventory leaked process, endpoint or policy identifiers")
    return report


def main():
    if os.name != "nt":
        raise SystemExit("Windows hosted BFE test only")
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    before = snapshot(agent)

    errors = []
    accepted = threading.Event()
    stop = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(4)
        port = listener.getsockname()[1]

        def server():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    if connection.recv(5) != b"probe":
                        raise AssertionError("Real TCP data was changed")
                    accepted.set()
                    if not stop.wait(5):
                        raise AssertionError("Windows BFE preflight probe timed out")
                    connection.sendall(b"done")
            except Exception as exc:
                errors.append(type(exc).__name__)

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=4) as client:
                client.settimeout(5)
                client.sendall(b"probe")
                if not accepted.wait(4):
                    raise AssertionError("Independent Windows TCP connection not established")
                # Probe real BFE *while* a separate actual TCP connection is live.
                during = snapshot(agent)
                stop.set()
                if client.recv(4) != b"done":
                    raise AssertionError("Windows TCP connection failed after WFP read-only query")
        finally:
            stop.set()
            thread.join(timeout=6)
        if thread.is_alive() or errors:
            raise AssertionError("Independent live Windows TCP process failed")

    after = snapshot(agent)
    # Windows may legitimately change filter inventory concurrently; never
    # mistake a changing count for a FlowBridge policy mutation.
    report = {
        "kind": "real_windows_bfe_readonly_with_live_tcp_and_original_rust",
        "passed": True,
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "agent_sha256": hashlib.sha256(agent.read_bytes()).hexdigest(),
        "wfp_engine_opened_three_times": True,
        "actual_bfe_filter_enumeration": True,
        "live_tcp_while_reading_bfe": True,
        "real_tcp_survived_bfe_read": True,
        "before_filter_sample": before["filter_sample_count"],
        "during_filter_sample": during["filter_sample_count"],
        "after_filter_sample": after["filter_sample_count"],
        "all_samples_complete": all(
            item["sample_complete"] for item in (before, during, after)
        ),
        "filter_count_change_not_attributed_to_agent": True,
        "process_and_policy_identity_redacted": True,
        "filter_policy_modified": False,
        "ndisrd_mode_modified": False,
        "driver_installed_by_test": False,
        "native_packet_pid_bound": False,
        "arbitrary_selected_app_accepted": False,
        "crash_persistent_fail_closed": False,
        "wfp_ndisrd_ordering_proved": False,
        "dns_leak_free": False,
        "win10_11_acceptance": False,
        "release_accepted": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
