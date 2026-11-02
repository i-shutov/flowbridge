#!/usr/bin/env python3
"""Real hosted-only WFP persistent canary, crash survival + independent SYSTEM rollback."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import subprocess
import tempfile
import threading
import time

TOKEN = "HOSTED_PERSISTENT_WFP_QA_WITH_INDEPENDENT_SYSTEM_RESCUE"
TASK = "FlowBridge_Wfp_Persistent_Qa_Rescue"
CLIENTS = {
    "tcp4": ("wfp-qa-client", "DYNAMIC_WFP_QA_LOOPBACK_ONLY"),
    "udp4": ("wfp-qa-udp4-client", "DYNAMIC_WFP_QA_UDP4_APP_PORT_ONLY"),
    "tcp6": ("wfp-qa-tcp6-client", "DYNAMIC_WFP_QA_TCP6_APP_PORT_ONLY"),
    "udp6": ("wfp-qa-udp6-client", "DYNAMIC_WFP_QA_UDP6_APP_PORT_ONLY"),
}


def call(exe, *args, env=None):
    p = subprocess.run([str(exe), *map(str, args)], capture_output=True,
                       text=True, encoding="utf-8", timeout=9, env=env)
    return p.returncode, json.loads(p.stdout)


def state(exe):
    code, r = call(exe, "wfp-qa-persist-status", TOKEN)
    assert code == 0 and r["protected_fail_closed"] is False
    return (r["qa_filter_present"], r["qa_sublayer_present"])


def cleanup(exe):
    code, r = call(exe, "wfp-qa-persist-remove", TOKEN)
    assert code == 0 and r["qa_filter_and_sublayer_absent"]
    assert state(exe) == (False, False)


def ps(script, env):
    p = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive",
                        "-Command", script], env=env, capture_output=True,
                       text=True, timeout=20)
    if p.returncode:
        raise RuntimeError("SYSTEM recovery task creation/removal failed")


def rescue(exe):
    env = dict(os.environ, FB_EXE=str(exe), FB_TASK=TASK)
    ps(r"""
$ErrorActionPreference='Stop'
if (Get-ScheduledTask -TaskName $env:FB_TASK -ErrorAction SilentlyContinue) {
    throw 'Unexpected existing recovery task'
}
$a=New-ScheduledTaskAction -Execute $env:FB_EXE -Argument 'wfp-qa-persist-remove HOSTED_PERSISTENT_WFP_QA_WITH_INDEPENDENT_SYSTEM_RESCUE'
$t=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(3)
Register-ScheduledTask -TaskName $env:FB_TASK -Action $a -Trigger $t -User SYSTEM -RunLevel Highest -Force | Out-Null
Get-ScheduledTask -TaskName $env:FB_TASK -ErrorAction Stop | Out-Null
""", env)


def disarm():
    ps(r"""
$ErrorActionPreference='Stop'
Unregister-ScheduledTask -TaskName $env:FB_TASK -Confirm:$false -ErrorAction Stop
if (Get-ScheduledTask -TaskName $env:FB_TASK -ErrorAction SilentlyContinue) {
    throw 'Recovery task persists'
}
""", dict(os.environ, FB_TASK=TASK))


class Echo:
    def __init__(self, protocol):
        self.ipv6 = protocol.endswith("6")
        self.udp = protocol.startswith("udp")
        self.host = "::1" if self.ipv6 else "127.0.0.1"
        af = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        typ = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        for _ in range(20):
            self.s = socket.socket(af, typ)
            self.s.bind((self.host, 0))
            self.port = self.s.getsockname()[1]
            if 49152 <= self.port <= 65534:
                break
            self.s.close()
        else:
            raise RuntimeError("Dedicated high port unavailable")
        if not self.udp:
            self.s.listen(8)
        self.s.settimeout(.15)
        self.hits = 0
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        while not self.stop.is_set():
            try:
                if self.udp:
                    data, addr = self.s.recvfrom(32)
                    self.hits += 1
                    if data == b"probe":
                        self.s.sendto(b"done", addr)
                else:
                    conn, _ = self.s.accept()
                    with conn:
                        conn.settimeout(1)
                        data = bytearray()
                        while len(data) <= 32:
                            part = conn.recv(32)
                            if not part:
                                break
                            data.extend(part)
                        self.hits += 1
                        if data == b"probe":
                            conn.sendall(b"done")
            except (socket.timeout, OSError):
                continue

    def __enter__(self):
        self.worker.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.s.close()
        self.worker.join(timeout=2)


def rust_client(exe, proto, port):
    command, consent = CLIENTS[proto]
    code, r = call(exe, command, port, consent)
    if code == 0:
        assert r["ok"] is True and r["ndisrd_touched"] is False
        return True
    assert r["ok"] is False
    return False


def py_client(e, proto):
    with socket.socket(socket.AF_INET6 if e.ipv6 else socket.AF_INET,
                       socket.SOCK_DGRAM if e.udp else socket.SOCK_STREAM) as s:
        s.settimeout(2)
        if e.udp:
            s.sendto(b"probe", (e.host, e.port))
            return s.recvfrom(8)[0] == b"done"
        s.connect((e.host, e.port))
        s.sendall(b"probe")
        s.shutdown(socket.SHUT_WR)
        return s.recv(8) == b"done"


def phase(agent, selected, sibling, proto):
    checks = {}
    guard = None
    rescue_armed = False
    with Echo(proto) as e:
        checks["pre_selected"] = rust_client(selected, proto, e.port)
        checks["pre_sibling"] = rust_client(sibling, proto, e.port)
        checks["pre_python"] = py_client(e, proto)
        assert all(checks.values()) and state(agent) == (False, False)
        try:
            rescue(agent)
            rescue_armed = True
            checks["independent_system_rescue_armed"] = True
            env = dict(os.environ, FLOWBRIDGE_WFP_QA_SYSTEM_RESCUE_ARMED="1")
            guard = subprocess.Popen(
                [str(agent), "wfp-qa-persist-arm", str(selected), str(e.port), proto, TOKEN],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", env=env)
            messages = queue.Queue(maxsize=1)
            threading.Thread(target=lambda: messages.put(guard.stdout.readline()),
                             daemon=True).start()
            try:
                line = messages.get(timeout=9)
            except queue.Empty:
                raise RuntimeError("Persistent BFE guard not ready") from None
            assert line and guard.poll() is None
            ready = json.loads(line)
            assert ready["ok"] and ready["bfe_filter_readback_verified"]
            assert ready["persistent_filter"] and ready["system_rescue_prearmed"]
            assert ready["selected_high_port_only"] and ready["transport"] == proto
            checks["persistent_readback"] = state(agent) == (True, True)
            before = e.hits
            checks["selected_denied"] = not rust_client(selected, proto, e.port)
            time.sleep(.2)
            checks["selected_not_delivered"] = e.hits == before
            checks["sibling_allowed"] = rust_client(sibling, proto, e.port)
            checks["python_allowed"] = py_client(e, proto)
            assert all(checks.values())
            guard.kill()
            guard.wait(timeout=5)
            guard = None
            checks["guard_killed"] = True
            checks["persistent_after_crash"] = state(agent) == (True, True)
            checks["still_denied"] = not rust_client(selected, proto, e.port)
            checks["sibling_survived"] = rust_client(sibling, proto, e.port)
            assert all(checks.values())
            cleanup(agent)
            checks["cleanup_verified"] = True
            checks["selected_recovered"] = rust_client(selected, proto, e.port)
            assert all(checks.values())
        finally:
            if guard:
                guard.kill()
                guard.wait(timeout=5)
            # On failed explicit cleanup, preserve independent SYSTEM rescue.
            cleanup(agent)
            if rescue_armed:
                disarm()
    return checks


def main():
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or \
       os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Never execute persistent WFP experiment on paid self-hosted VPS")
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    report = {
        "kind": "real_hosted_wfp_persistent_canary_crash_survival",
        "passed": False, "phases": {},
        "ndisrd_modified": False,"general_selected_app_accepted": False,
        "packet_to_pid_proven": False,"protected_fail_closed": False,
        "dns_leak_free": False,"win10_11_accepted": False,"release_accepted": False
    }
    try:
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"],
                                         prefix="fb-wfp-persistence-") as folder:
            selected = Path(folder) / "FlowBridgeWfpLabClient.exe"
            sibling = Path(folder) / "FlowBridgeWfpOtherClient.exe"
            shutil.copy2(agent, selected)
            shutil.copy2(agent, sibling)
            assert hashlib.sha256(selected.read_bytes()).digest() == \
                   hashlib.sha256(sibling.read_bytes()).digest()
            for proto in ("tcp4","udp4","tcp6","udp6"):
                report["phases"][proto] = phase(agent, selected, sibling, proto)
            report["passed"] = True
    except Exception as exc:
        report["error_class"] = type(exc).__name__
        raise
    finally:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
