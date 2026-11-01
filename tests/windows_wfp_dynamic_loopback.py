#!/usr/bin/env python3
"""Actual Windows WFP dynamic app-specific block and forced-death cleanup.

Uses a copied original Rust client executable and real TCP. Does NOT prove
persistent fail-closed, NDISRD packet ownership, or Windows 10/11 acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import socketserver
import subprocess
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

def client(exe, port):
    return subprocess.run(
        [str(exe), "wfp-qa-client", str(port), CONSENT],
        capture_output=True, text=True, encoding="utf-8", timeout=8)

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
    return data["own_app_id_equals_target"]


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
            identity = {
                "selected_self_matches_target": identity_probe(qa, qa),
                "different_copy_self_matches_target": identity_probe(other, qa),
                "agent_self_matches_target": identity_probe(agent, qa),
            }

            def run_trial(guard_consent, app_only=False, port_only=False,
                          guard_executable=None):
                guard = subprocess.Popen(
                    [str(guard_executable or agent), "wfp-qa-guard",
                     str(qa), str(port), guard_consent],
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
                    assert ready["dynamic_private_sublayer"] is True
                    assert ready["filter_persistent"] is False
                    assert ready["diagnostic_app_id_only"] is app_only
                    assert ready["diagnostic_port_only"] is port_only
                    assert ready["app_id_scoped"] is (not port_only)
                    assert ready["tcp_port_scoped"] is (not app_only)
                    trial["ready"] = True
                    time.sleep(.2)
                    blocked = client(qa, port)
                    trial["selected_denied"] = (
                        blocked.returncode != 0 and
                        "WFP QA TCP connect denied" in blocked.stdout)
                    other_result = client(other, port)
                    trial["different_executable_allowed"] = other_result.returncode == 0
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=2) as independent:
                            independent.sendall(b"probe")
                            independent.shutdown(socket.SHUT_WR)
                            trial["python_allowed"] = independent.recv(4) == b"done"
                    except OSError:
                        trial["python_allowed"] = False
                finally:
                    if guard.poll() is None:
                        guard.kill()
                    guard.wait(timeout=8)
                for attempt in range(15):
                    recovered = client(qa, port)
                    if recovered.returncode == 0:
                        break
                    time.sleep(.2)
                trial["recovered"] = recovered.returncode == 0
                return trial

            # Port-only must deny ALL clients on the one unique ephemeral QA
            # port; AppId-only and precise trials must deny only selected EXE.
            # This discriminates ineffective BFE filtering from AppId mismatch.
            port_trial = run_trial("DYNAMIC_WFP_QA_PORT_ONLY_DIAGNOSTIC", port_only=True)
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
            passed = (
                identity["selected_self_matches_target"] is True and
                identity["different_copy_self_matches_target"] is False and
                identity["agent_self_matches_target"] is False and
                all(
                stage["ready"] and stage["selected_denied"] and
                stage["different_executable_allowed"] is (not stage["port_only"]) and
                stage["python_allowed"] is (not stage["port_only"]) and
                stage["recovered"] for stage in stages)
            )
            result = {
                "kind": "original_rust_real_wfp_dynamic_qa_diagnostic_matrix",
                "passed": passed,
                "source_commit": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], text=True).strip(),
                "agent_sha256": digest,
                "copied_client_sha256": hashlib.sha256(qa.read_bytes()).hexdigest(),
                "app_id_lookup_consistency": identity,
                "port_only_trial": port_trial,
                "app_id_only_trial": identity_trial,
                "app_id_port_protocol_trial": precise_trial,
                "self_guard_app_id_only_trial": self_guard_app_only,
                "self_guard_app_id_port_trial": self_guard_precise,
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
