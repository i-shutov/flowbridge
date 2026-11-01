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
        shutil.copy2(agent, qa)
        other_qa = Path(folder) / "FlowBridgeWfpOtherClient.exe"
        shutil.copy2(agent, other_qa)
        digest = hashlib.sha256(agent.read_bytes()).hexdigest()
        assert hashlib.sha256(qa.read_bytes()).hexdigest() == digest
        assert hashlib.sha256(other_qa.read_bytes()).hexdigest() == digest
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            denied_optin = subprocess.run(
                [str(agent), "wfp-qa-guard", str(qa), str(port), "DENY"],
                capture_output=True, text=True, timeout=5)
            assert denied_optin.returncode != 0
            baseline = client(qa, port)
            assert baseline.returncode == 0
            assert json.loads(baseline.stdout)["real_tcp_half_close"] is True
            guard = subprocess.Popen(
                [str(agent), "wfp-qa-guard", str(qa), str(port), CONSENT],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, encoding="utf-8")
            q = queue.Queue(maxsize=1)
            threading.Thread(target=lambda: q.put(guard.stdout.readline()), daemon=True).start()
            try:
                ready = json.loads(q.get(timeout=10))
                assert ready["wfp_ale_block_installed"] is True
                assert ready["filter_persistent"] is False
                assert ready["dynamic_private_sublayer"] is True
                time.sleep(.2)
                blocked = client(qa, port)
                assert blocked.returncode != 0, "WFP installed but selected QA client still connected"
                allowed_other_exe = client(other_qa, port)
                assert allowed_other_exe.returncode == 0, "Different-path client wrongly blocked"
                assert "WFP QA TCP connect denied" in blocked.stdout
                with socket.create_connection(("127.0.0.1", port), timeout=2) as independent:
                    independent.sendall(b"probe")
                    independent.shutdown(socket.SHUT_WR)
                    assert independent.recv(4) == b"done"
            finally:
                if guard.poll() is None:
                    guard.kill()
                guard.wait(timeout=8)
            for _ in range(15):
                recovered = client(qa, port)
                if recovered.returncode == 0:
                    break
                time.sleep(.2)
            assert recovered.returncode == 0, "Dynamic rule outlived guard"
            result = {
                "kind":"original_rust_real_wfp_dynamic_qa_lifecycle",
                "passed":True,
                "source_commit":subprocess.check_output(["git","rev-parse","HEAD"], text=True).strip(),
                "agent_sha256":digest,
                "copied_client_sha256":hashlib.sha256(qa.read_bytes()).hexdigest(),
                "actual_wfp_ale_block":True,
                "selected_qa_executable_denied":True,
                "different_executable_allowed":True,
                "dynamic_private_sublayer_removed_with_session":True,
                "unrelated_python_executable_allowed":True,
                "guard_forcibly_killed":True,
                "dynamic_filter_removed_after_guard_death":True,
                "real_tcp_half_close":True,
                "persistent_filter_created":False,
                "ndisrd_modified":False,
                "wfp_ndisrd_ordering_proved":False,
                "arbitrary_packet_pid_bound":False,
                "crash_persistent_fail_closed":False,
                "dns_leak_free":False,
                "win10_11_acceptance":False,
                "release_accepted":False
            }
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(result))
        finally:
            server.shutdown()
            server_thread.join(timeout=4)

if __name__ == "__main__":
    main()
