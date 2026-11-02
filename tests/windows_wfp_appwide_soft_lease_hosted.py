#!/usr/bin/env python3
"""Native hosted Windows: persistent AppId DENY plus crash-revoked SOFT permit.

This explicitly permits ONE high-port QA socket while the supervised lease
process is alive. No NDISRD, no arbitrary app, no protected-mode claim.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import subprocess
import time
import tempfile
import threading

from windows_wfp_appwide_hosted import TOKEN, arm_rescue, remove_rescue, cleanup, status
from windows_wfp_persistent_hosted import Echo, call, py_client, rust_client

LEASE_TOKEN = "HOSTED_WFP_SOFT_LEASE_QA_WITH_INDEPENDENT_SYSTEM_RESCUE"


def checked_lease_state(agent):
    code, value = call(agent, "wfp-qa-appwide-soft-status", LEASE_TOKEN)
    assert code == 0 and value["ok"]
    assert value["dynamic_session_only"] and not value["hard_permit"]
    assert not value["ndisrd_modified"] and not value["protected_fail_closed"]
    assert not value["release_accepted"] and not value["dns_leak_free"]
    return value["soft_lease_ipv4_present"], value["soft_lease_ipv6_present"]


def launch(agent, command, args, env, label):
    proc = subprocess.Popen([str(agent), command, *map(str, args)],
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
    q = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: q.put(proc.stdout.readline()), daemon=True).start()
    try:
        data = q.get(timeout=12)
        assert data and proc.poll() is None, label + " exited before readiness"
        result = json.loads(data)
        assert result["ok"] and not result["release_accepted"]
        return proc, result
    except Exception:
        proc.kill()
        proc.wait(timeout=5)
        raise




class HeldEcho(Echo):
    """Regular 'probe' echo plus a long-lived selected TCP stream on ONE port."""
    def __init__(self):
        super().__init__("tcp4")
        self.held_hits = []

    def serve_one(self, conn):
        with conn:
            conn.settimeout(.5)
            pending = bytearray()
            while not self.stop.is_set():
                try:
                    chunk = conn.recv(32)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not chunk:
                    return
                pending.extend(chunk)
                if pending.startswith(b"probe") and len(pending) >= 5:
                    self.hits += 1
                    try:
                        conn.sendall(b"done")
                    except OSError:
                        pass
                    return
                while pending.startswith(b"HELD") and len(pending) >= 8:
                    one = bytes(pending[:8])
                    del pending[:8]
                    if one not in (b"HELD0001", b"HELD0002"):
                        return
                    self.held_hits.append(one)
                    try:
                        conn.sendall(one)
                    except OSError:
                        return
                if len(pending) > 32:
                    return

    def serve(self):
        workers = []
        while not self.stop.is_set():
            try:
                conn, _ = self.s.accept()
            except (socket.timeout, OSError):
                continue
            worker = threading.Thread(target=self.serve_one, args=(conn,), daemon=True)
            worker.start()
            workers.append(worker)
        for worker in workers:
            worker.join(timeout=.4)


def held_after_revocation(proc):
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write("PROBE\n")
    proc.stdin.flush()
    result = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: result.put(proc.stdout.readline()),
                     daemon=True).start()
    value = json.loads(result.get(timeout=8))
    assert value["ok"] is True and not value["release_accepted"]
    assert not value["ndisrd_modified"] and not value["protected_fail_closed"]
    return value["existing_flow_delivered_after_lease_death"]


def main():
    if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("Soft WFP lease requires GitHub-hosted Windows")
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    report = {
        "kind": "native_wfp_soft_lease_over_persistent_appwide_deny",
        "passed": False, "checks": {},
        "driver_used": False, "native_packet_to_pid": False,
        "nonleased_port_bypass": False, "hard_permit": False,
        "protected_fail_closed": False, "dns_leak_free": False,
        "win10_11_accepted": False, "release_accepted": False,
    }
    guard = None
    lease = None
    veto = None
    held = None
    rescue_armed = False
    cleaned = False
    checks = report["checks"]
    try:
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"],
                                         prefix="fb-soft-wfp-") as folder, ExitStack() as stack:
            selected = Path(folder) / "FlowBridgeWfpLabClient.exe"
            sibling = Path(folder) / "FlowBridgeWfpOtherClient.exe"
            shutil.copy2(agent, selected)
            shutil.copy2(agent, sibling)
            assert hashlib.sha256(selected.read_bytes()).digest() == \
                   hashlib.sha256(sibling.read_bytes()).digest()
            allowed = stack.enter_context(HeldEcho())
            denied = stack.enter_context(Echo("tcp4"))
            held_server = allowed
            assert allowed.port != denied.port
            assert status(agent) == (False, False, False)
            assert checked_lease_state(agent) == (False, False)

            # None of these inputs can leave a temporary WFP exception.
            for token, port, path in (
                ("DENY", allowed.port, selected),
                (LEASE_TOKEN, 53, selected),
                (LEASE_TOKEN, allowed.port, sibling),
            ):
                code, result = call(agent, "wfp-qa-appwide-soft-lease", path, port, token)
                assert code != 0 and result["ok"] is False
            checks["no_consent_no_unsafe_port_no_other_app"] = True
            checks["unarmed_permit_denied"] = checked_lease_state(agent) == (False, False)
            checks["baseline_selected"] = rust_client(selected, "tcp4", allowed.port)
            checks["baseline_sibling"] = rust_client(sibling, "tcp4", allowed.port)
            checks["baseline_python"] = py_client(allowed, "tcp4")
            assert all(checks.values())

            arm_rescue(agent)
            rescue_armed = True
            env = dict(os.environ, FLOWBRIDGE_WFP_APPWIDE_SYSTEM_RESCUE_ARMED="1")
            guard, started = launch(agent, "wfp-qa-appwide-arm",
                                    (selected, TOKEN), env, "Persistent guard")
            assert started["persistent"] and started["bfe_readback"]
            checks["persistent_ipv4_ipv6_ready"] = status(agent) == (True, True, True)
            checks["persistent_selected_denied"] = not rust_client(selected, "tcp4", allowed.port)
            checks["persistent_other_port_denied"] = not rust_client(selected, "tcp4", denied.port)
            checks["persistent_sibling_allowed"] = rust_client(sibling, "tcp4", allowed.port)
            assert all(checks.values())

            lease, ready = launch(agent, "wfp-qa-appwide-soft-lease",
                                  (selected, allowed.port, LEASE_TOKEN), env, "Soft lease")
            assert ready["soft_permit_readback"] and ready["dynamic_session"]
            assert ready["persistent_deny_still_present"] and ready["lease_port_restricted"]
            assert not ready["hard_permit"] and not ready["protected_fail_closed"]
            checks["dynamic_soft_lease_readback"] = checked_lease_state(agent) == (True, True)
            checks["persistent_deny_still_readable"] = status(agent) == (True, True, True)
            checks["only_test_port_admitted"] = rust_client(selected, "tcp4", allowed.port)
            checks["other_port_still_denied"] = not rust_client(selected, "tcp4", denied.port)
            checks["sibling_unchanged"] = rust_client(sibling, "tcp4", denied.port)
            checks["python_unchanged"] = py_client(denied, "tcp4")
            assert all(checks.values()), checks

            # A second, independent BFE sublayer must retain veto power.
            veto, veto_ready = launch(
                agent, "wfp-qa-tcp4-guard",
                (selected, allowed.port, "DYNAMIC_WFP_QA_TCP4_APP_PORT_ONLY"),
                dict(os.environ), "Independent WFP sublayer")
            checks["independent_veto_readback"] = (
                veto_ready["wfp_ale_block_installed"]
                and veto_ready["dynamic_private_sublayer"])
            checks["independent_sublayer_vetoes_soft_permit"] = (
                not rust_client(selected, "tcp4", allowed.port))
            checks["independent_veto_not_global"] = (
                rust_client(sibling, "tcp4", allowed.port)
                and py_client(allowed, "tcp4"))
            assert all(checks.values()), checks
            veto.kill()
            veto.wait(timeout=5)
            veto = None
            checks["selected_recovers_after_independent_veto_death"] = (
                rust_client(selected, "tcp4", allowed.port))
            assert all(checks.values()), checks

            # Keep an ALREADY-ESTABLISHED selected socket alive across lease
            # process death. A new-connection denial alone proves too little.
            held, initial = launch(
                agent, "wfp-qa-appwide-held-tcp4-client",
                (held_server.port, LEASE_TOKEN), dict(os.environ), "Held TCP")
            checks["held_tcp_live_before_crash"] = (
                initial["connection_established_before_lease_death"]
                and held_server.held_hits == [b"HELD0001"])
            assert all(checks.values()), checks

            # Strongest check: no explicit release path. Windows must close
            # the dynamic BFE session after killing its process.
            lease.kill()
            lease.wait(timeout=5)
            lease = None
            checks["lease_killed"] = True
            checks["lease_filters_removed_automatically"] = checked_lease_state(agent) == (False, False)
            # Allow Windows ALE/BFE reauthorization to settle, then send on
            # the SAME socket. Observe both client result and server receipt.
            time.sleep(.5)
            after_delivered = held_after_revocation(held)
            held.wait(timeout=5)
            held = None
            checks["held_tcp_revoked_on_lease_crash"] = (
                not after_delivered and held_server.held_hits == [b"HELD0001"])
            checks["persistent_after_lease_death"] = status(agent) == (True, True, True)
            checks["selected_denied_again"] = not rust_client(selected, "tcp4", allowed.port)
            checks["sibling_still_allowed"] = rust_client(sibling, "tcp4", allowed.port)
            assert all(checks.values()), checks

            guard.kill()
            guard.wait(timeout=5)
            guard = None
            checks["guard_killed"] = True
            checks["persistent_survives_guard_crash"] = status(agent) == (True, True, True)
            checks["selected_stays_denied"] = not rust_client(selected, "tcp4", allowed.port)
            assert all(checks.values()), checks
            cleanup(agent)
            cleaned = True
            checks["exact_recovery"] = status(agent) == (False, False, False)
            checks["lease_still_absent"] = checked_lease_state(agent) == (False, False)
            checks["selected_restored"] = rust_client(selected, "tcp4", allowed.port)
            checks["other_port_restored"] = rust_client(selected, "tcp4", denied.port)
            assert all(checks.values()), checks
            report["passed"] = True
    except Exception as exc:
        report["error_class"] = type(exc).__name__
        raise
    finally:
        for proc in (held, veto, lease, guard):
            if proc is not None:
                proc.kill()
                proc.wait(timeout=5)
        if rescue_armed:
            if not cleaned:
                # A failed cleanup leaves the independent SYSTEM rescue armed.
                cleanup(agent)
            remove_rescue()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
