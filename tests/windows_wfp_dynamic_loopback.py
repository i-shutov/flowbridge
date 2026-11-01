#!/usr/bin/env python3
"""Actual Windows WFP dynamic app-specific block and forced-death cleanup.

Uses a copied original Rust client executable and real TCP. Does NOT prove
persistent fail-closed, NDISRD packet ownership, or Windows 10/11 acceptance.
"""
import argparse
import hashlib
import json
import ipaddress
import os
from pathlib import Path
import queue
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

CONSENT = "DYNAMIC_WFP_QA_LOOPBACK_ONLY"

class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        payload = bytearray()
        while chunk := self.request.recv(1024):
            payload.extend(chunk)
        if payload == b"probe":
            self.request.sendall(b"done")

def client(exe, port, ip="127.0.0.1"):
    command = ([str(exe), "wfp-qa-client", str(port), CONSENT]
               if ip == "127.0.0.1" else
               [str(exe), "wfp-qa-client-local-ipv4", ip, str(port), CONSENT])
    return subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", timeout=8)


def local_interface_candidate():
    """Host-owned non-127 IPv4 only. UDP route lookup sends zero datagrams."""
    candidates = set()
    try:
        candidates.update(item[4][0] for item in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM))
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))  # no send; local routing lookup
            candidates.add(sock.getsockname()[0])
    except OSError:
        pass
    for text in sorted(candidates):
        try:
            ip = ipaddress.IPv4Address(text)
        except ipaddress.AddressValueError:
            continue
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((text, 0))  # proves assigned local address
            return text
        except OSError:
            continue
    return None

def identity_probe(exe, target):
    # Run the actual Windows executable, not a mocked ID resolver. The
    # original Rust code compares BFE-owned AppId blobs in-process and only
    # reveals an equality boolean, never paths, blobs or process identities.
    result = subprocess.run(
        [str(exe), "wfp-qa-identity", str(target), CONSENT],
        capture_output=True, text=True, encoding="utf-8", timeout=8)
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["ok"] is True and data["redacted"] is True
    assert data["wfp_filter_created"] is False
    assert data["packet_pid_bound"] is False
    assert data["file_handle_native_path_checked"] is True
    return data


def main():
    if os.name != "nt":
        raise RuntimeError("Windows WFP native QA only")
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="flowbridge-wfp-qa-") as folder, \
         Server(("127.0.0.1", 0), Handler) as server:
        qa = Path(folder) / "FlowBridgeWfpLabClient.exe"
        other = Path(folder) / "FlowBridgeWfpOtherClient.exe"
        for path in (qa, other):
            shutil.copy2(agent, path)
        digest = hashlib.sha256(agent.read_bytes()).hexdigest()
        assert all(hashlib.sha256(p.read_bytes()).hexdigest() == digest for p in (qa, other))
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            denied = subprocess.run(
                [str(agent), "wfp-qa-guard", str(qa), str(port), "DENY"],
                capture_output=True, text=True, timeout=5)
            assert denied.returncode != 0
            baseline = client(qa, port)
            assert baseline.returncode == 0
            assert json.loads(baseline.stdout)["real_tcp_half_close"] is True
            # Both QA processes have byte-identical PE images, but different
            # absolute paths. This distinguishes BFE app-ID lookup identity
            # from filter classification; no hash or path enters the report.
            selected_identity = identity_probe(qa, qa)
            other_identity = identity_probe(other, qa)
            agent_identity = identity_probe(agent, qa)
            identity = {
                "selected_self_matches_target": selected_identity["own_app_id_equals_target"],
                "different_copy_self_matches_target": other_identity["own_app_id_equals_target"],
                "agent_self_matches_target": agent_identity["own_app_id_equals_target"],
                "selected_running_image_equals_handle": selected_identity["own_native_image_equals_handle"],
                "different_running_image_equals_handle": other_identity["own_native_image_equals_handle"],
                "selected_input_equals_handle_appid": selected_identity["target_input_appid_equals_handle_canonical"],
                "different_input_equals_handle_appid": other_identity["own_input_appid_equals_handle_canonical"],
            }

            def run_trial(guard_consent, app_only=False, port_only=False,
                          guard_executable=None, probe_ip="127.0.0.1",
                          probe_port=None, inspect_events=False):
                selected_port = port if probe_port is None else probe_port
                guard = subprocess.Popen(
                    [str(guard_executable or agent), "wfp-qa-guard",
                     str(qa), str(selected_port), guard_consent],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, encoding="utf-8")
                q = queue.Queue(maxsize=1)
                threading.Thread(target=lambda: q.put(guard.stdout.readline()),
                                 daemon=True).start()
                trial = {"app_only": app_only, "port_only": port_only,
                         "guard_from_selected_exe": guard_executable == qa,
                         "ready": False, "selected_denied": False,
                         "different_executable_allowed": False, "python_allowed": False,
                         "recovered": False}
                try:
                    ready = json.loads(q.get(timeout=10))
                    assert ready["wfp_ale_block_installed"] is True
                    assert ready["bfe_filter_readback_verified"] is True
                    assert ready["app_id_from_canonical_file_handle"] is True
                    assert ready["dynamic_private_sublayer"] is True
                    assert ready["filter_persistent"] is False
                    assert ready["diagnostic_app_id_only"] is app_only
                    assert ready["diagnostic_port_only"] is port_only
                    assert ready["app_id_scoped"] is (not port_only)
                    assert ready["tcp_port_scoped"] is (not app_only)
                    # Filter ID belongs only to this ephemeral guard. Do not
                    # write it to a report or print it to CI logs.
                    filter_id = int(ready["ephemeral_filter_id"])
                    assert filter_id > 0
                    trial["ready"] = True
                    time.sleep(.2)
                    blocked = client(qa, selected_port, probe_ip)
                    trial["selected_denied"] = (
                        blocked.returncode != 0 and
                        "WFP QA TCP connect denied" in blocked.stdout)
                    other_result = client(other, selected_port, probe_ip)
                    trial["different_executable_allowed"] = other_result.returncode == 0
                    try:
                        with socket.create_connection((probe_ip, selected_port), timeout=2) as independent:
                            independent.sendall(b"probe")
                            independent.shutdown(socket.SHUT_WR)
                            trial["python_allowed"] = independent.recv(4) == b"done"
                    except OSError:
                        trial["python_allowed"] = False
                    if inspect_events:
                        # Read the actual CLASSIFY_DROP.filterId while the QA
                        # filter still exists; a coincidental port event is
                        # NOT proof of this filter's runtime classification.
                        if guard.poll() is not None:
                            trial["event_probe"] = {"query_succeeded": False,
                                                    "active_qa_filter_verified": False}
                        else:
                            event = subprocess.run(
                                [str(agent), "wfp-qa-event-identity", str(qa),
                                 str(other), str(Path(sys.executable).resolve()),
                                 str(agent), str(selected_port), str(filter_id), CONSENT],
                                capture_output=True, text=True, encoding="utf-8",
                                timeout=8)
                            if event.returncode != 0:
                                trial["event_probe"] = {"query_succeeded": False,
                                                        "error_class": "ChildExit"}
                            else:
                                trial["event_probe"] = json.loads(event.stdout)
                finally:
                    if guard.poll() is None:
                        guard.kill()
                    guard.wait(timeout=8)
                for attempt in range(15):
                    recovered = client(qa, selected_port, probe_ip)
                    if recovered.returncode == 0:
                        break
                    time.sleep(.2)
                trial["recovered"] = recovered.returncode == 0
                return trial

            # Port-only must deny ALL clients on the one unique ephemeral QA
            # port; AppId-only and precise trials must deny only selected EXE.
            # This discriminates ineffective BFE filtering from AppId mismatch.
            port_trial = run_trial(
                "DYNAMIC_WFP_QA_PORT_ONLY_DIAGNOSTIC",
                port_only=True, inspect_events=True)
            # Correlate a *live* exact BFE filter ID to actual classify-drop
            # events, never arbitrary coincident TCP-port events. Every result
            # is redacted and a missing event remains explicitly INCONCLUSIVE.
            event_diagnostic = port_trial.pop("event_probe")
            assert event_diagnostic.get("filter_id_redacted", True) is True
            assert event_diagnostic.get("file_handle_native_identity_compared") is True
            assert event_diagnostic.get("kernel_packet_owner_bound", False) is False
            assert event_diagnostic.get("release_accepted", False) is False
            identity_trial = run_trial("DYNAMIC_WFP_QA_APP_ONLY_DIAGNOSTIC", app_only=True)
            precise_trial = run_trial(CONSENT)
            # Counterfactual: create exactly the same filter while the
            # guard itself is executing from the selected QA binary path.
            # If AppId matching changes, path/canonicalization may matter;
            # otherwise the failure is deeper in runtime BFE classification.
            self_guard_app_only = run_trial(
                "DYNAMIC_WFP_QA_APP_ONLY_DIAGNOSTIC",
                app_only=True, guard_executable=qa)
            self_guard_precise = run_trial(CONSENT, guard_executable=qa)
            stages = (port_trial, identity_trial, precise_trial,
                      self_guard_app_only, self_guard_precise)
            # Independent second route: same-host non-127 interface IPv4.
            # This is local-delivery traffic, not an external/on-wire trial.
            # Keep the original loopback matrix mandatory even if this passes.
            nic = {"available": False, "baseline_ok": False, "tested": False,
                   "port_only_trial": None, "app_id_only_trial": None,
                   "app_id_port_protocol_trial": None,
                   "app_id_scoped_proven": False,
                   "same_host_local_delivery_only": True,
                   "actual_external_network_traffic": False,
                   "host_network_modified": False, "ndisrd_modified": False,
                   "address_and_process_identity_redacted": True}
            nic_ip = local_interface_candidate()
            if nic_ip is not None:
                nic["available"] = True
                try:
                    with Server((nic_ip, 0), Handler) as nic_server:
                        nic_port = nic_server.server_address[1]
                        nic_thread = threading.Thread(
                            target=nic_server.serve_forever, daemon=True)
                        nic_thread.start()
                        try:
                            nic["baseline_ok"] = client(
                                qa, nic_port, nic_ip).returncode == 0
                            if nic["baseline_ok"]:
                                nic["tested"] = True
                                nic["port_only_trial"] = run_trial(
                                    "DYNAMIC_WFP_QA_PORT_ONLY_DIAGNOSTIC",
                                    port_only=True, probe_ip=nic_ip,
                                    probe_port=nic_port, inspect_events=True)
                                nic["read_only_net_event_appid_correlation"] = (
                                    nic["port_only_trial"].pop("event_probe"))
                                nic["app_id_only_trial"] = run_trial(
                                    "DYNAMIC_WFP_QA_APP_ONLY_DIAGNOSTIC",
                                    app_only=True, probe_ip=nic_ip,
                                    probe_port=nic_port)
                                nic["app_id_port_protocol_trial"] = run_trial(
                                    CONSENT, probe_ip=nic_ip, probe_port=nic_port)
                                a = nic["port_only_trial"]
                                b = nic["app_id_only_trial"]
                                c = nic["app_id_port_protocol_trial"]
                                nic["app_id_scoped_proven"] = (
                                    a["ready"] and a["selected_denied"] and
                                    not a["different_executable_allowed"] and
                                    not a["python_allowed"] and a["recovered"] and
                                    all(t["ready"] and t["selected_denied"] and
                                        t["different_executable_allowed"] and
                                        t["python_allowed"] and t["recovered"]
                                        for t in (b, c)))
                        finally:
                            nic_server.shutdown()
                            nic_thread.join(timeout=4)
                except (OSError, RuntimeError, AssertionError,
                        subprocess.TimeoutExpired) as error:
                    nic["error_class"] = type(error).__name__
            passed = (
                identity["selected_self_matches_target"] is True and
                identity["different_copy_self_matches_target"] is False and
                identity["agent_self_matches_target"] is False and
                all(
                stage["ready"] and stage["selected_denied"] and
                stage["different_executable_allowed"] is (not stage["port_only"]) and
                stage["python_allowed"] is (not stage["port_only"]) and
                stage["recovered"] for stage in stages) and
                event_diagnostic.get("query_succeeded") is True and
                event_diagnostic.get("active_qa_filter_verified") is True and
                (not nic["tested"] or nic["app_id_scoped_proven"])
            )
            result = {
                "kind": "original_rust_real_wfp_dynamic_qa_diagnostic_matrix",
                "passed": passed,
                "source_commit": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], text=True).strip(),
                "agent_sha256": digest,
                "copied_client_sha256": hashlib.sha256(qa.read_bytes()).hexdigest(),
                "app_id_lookup_consistency": identity,
                "bfe_stored_conditions_verified": all(s["ready"] for s in stages),
                "read_only_net_event_appid_correlation": event_diagnostic,
                "port_only_trial": port_trial,
                "app_id_only_trial": identity_trial,
                "app_id_port_protocol_trial": precise_trial,
                "self_guard_app_id_only_trial": self_guard_app_only,
                "self_guard_app_id_port_trial": self_guard_precise,
                "local_interface_ipv4_diagnostic": nic,
                "guard_killed_after_each_trial": True,
                "unrestricted_port_trial_qa_loopback_only": True,
                "persistent_filter_created": False,
                "ndisrd_modified": False,
                "wfp_ndisrd_ordering_proved": False,
                "arbitrary_packet_pid_bound": False,
                "crash_persistent_fail_closed": False,
                "dns_leak_free": False,
                "win10_11_acceptance": False,
                "release_accepted": False
            }
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(result))
            if not passed:
                raise RuntimeError("Actual WFP enforcement failed; inspect redacted matrix JSON")
        finally:
            server.shutdown()
            server_thread.join(timeout=4)


if __name__ == "__main__":
    main()
