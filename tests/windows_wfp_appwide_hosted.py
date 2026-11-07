#!/usr/bin/env python3
"""Real hosted Windows original-Rust persistent AppId-wide IPv4/IPv6 deny and recovery.

Never run on a paid self-hosted runner. This is NOT production fail-closed, DNS
leak-free, NDISRD interception or Win10/11 native acceptance.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading

from windows_wfp_persistent_hosted import Echo, call, py_client, rust_client

TOKEN = "HOSTED_WFP_APPWIDE_QA_WITH_INDEPENDENT_SYSTEM_RESCUE"
TASK = "FlowBridge_Wfp_Appwide_Qa_Rescue"
FAMILIES = ("tcp4", "udp4", "tcp6", "udp6")


def powershell(script, env):
    proc = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
                          env=env, capture_output=True, text=True, timeout=20)
    if proc.returncode:
        raise RuntimeError("Independent SYSTEM task registration/removal failed")


def arm_rescue(agent):
    env = dict(os.environ, FB_AGENT=str(agent), FB_TASK=TASK)
    powershell(r"""
$ErrorActionPreference='Stop'
if (Get-ScheduledTask -TaskName $env:FB_TASK -ErrorAction SilentlyContinue) {
  throw 'Pre-existing rescue task; refuse to overwrite'
}
$action = New-ScheduledTaskAction -Execute $env:FB_AGENT -Argument 'wfp-qa-appwide-remove HOSTED_WFP_APPWIDE_QA_WITH_INDEPENDENT_SYSTEM_RESCUE'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(3)
Register-ScheduledTask -TaskName $env:FB_TASK -Action $action -Trigger $trigger -User SYSTEM -RunLevel Highest | Out-Null
$task = Get-ScheduledTask -TaskName $env:FB_TASK -ErrorAction Stop
if ($task.Principal.UserId -notmatch 'SYSTEM') { throw 'Rescue task not SYSTEM' }
""", env)


def remove_rescue():
    powershell(r"""
$ErrorActionPreference='Stop'
Unregister-ScheduledTask -TaskName $env:FB_TASK -Confirm:$false -ErrorAction Stop
if (Get-ScheduledTask -TaskName $env:FB_TASK -ErrorAction SilentlyContinue) {
  throw 'Rescue task persisted'
}
""", dict(os.environ, FB_TASK=TASK))


def status(agent):
    code, report = call(agent, "wfp-qa-appwide-status", TOKEN)
    assert code == 0 and report["protected_fail_closed"] is False
    assert report["ndisrd_modified"] is False and report["release_accepted"] is False
    return (report["qa_ipv4_present"], report["qa_ipv6_present"],
            report["qa_sublayer_present"])


def cleanup(agent):
    code, report = call(agent, "wfp-qa-appwide-remove", TOKEN)
    assert code == 0 and report["qa_filters_and_sublayer_absent"] is True
    assert status(agent) == (False, False, False)


def probe(e, selected, sibling, expected_selected, checks, phase):
    family = ("udp" if e.udp else "tcp") + ("6" if e.ipv6 else "4")
    before = e.hits
    selected_ok = rust_client(selected, family, e.port)
    checks[f"{phase}_selected_{family}_{e.port}"] = selected_ok is expected_selected
    if not expected_selected:
        checks[f"{phase}_selected_unseen_{family}_{e.port}"] = e.hits == before
    checks[f"{phase}_sibling_{family}_{e.port}"] = rust_client(sibling, family, e.port)
    checks[f"{phase}_python_{family}_{e.port}"] = py_client(e, family)
    assert all(checks.values())


def main():
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or \
       os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("AppId-wide BFE test forbidden outside GitHub-hosted Windows")
    p = argparse.ArgumentParser()
    p.add_argument("--agent", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    agent = args.agent.resolve(strict=True)
    report = {
        "kind": "real_hosted_appwide_wfp_ipv4_ipv6_crash_survival",
        "passed": False, "checks": {}, "transport_count": 4,
        "different_high_ports_per_transport": 2,
        "ndisrd_modified": False, "arbitrary_packet_pid_binding": False,
        "dns_leak_free": False, "protected_fail_closed": False,
        "win10_11_accepted": False, "release_accepted": False
    }
    guard = None
    rescue_armed = False
    cleaned = False
    try:
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"],
                                         prefix="fb-appwide-") as folder, ExitStack() as stack:
            selected = Path(folder) / "FlowBridgeWfpLabClient.exe"
            sibling = Path(folder) / "FlowBridgeWfpOtherClient.exe"
            shutil.copy2(agent, selected)
            shutil.copy2(agent, sibling)
            assert hashlib.sha256(selected.read_bytes()).digest() == \
                   hashlib.sha256(sibling.read_bytes()).digest()
            servers = [stack.enter_context(Echo(family)) for family in FAMILIES
                       for _ in range(2)]
            assert all(49152 <= e.port <= 65534 for e in servers)
            assert all(len({e.port for e in servers if
                           ("udp" if e.udp else "tcp")+("6" if e.ipv6 else "4") == family}) == 2
                       for family in FAMILIES)
            assert status(agent) == (False, False, False)
            checks = report["checks"]
            for server in servers:
                probe(server, selected, sibling, True, checks, "before")
            arm_rescue(agent)
            rescue_armed = True
            checks["independent_system_rescue"] = True
            env = dict(os.environ, FLOWBRIDGE_WFP_APPWIDE_SYSTEM_RESCUE_ARMED="1")
            guard = subprocess.Popen([str(agent), "wfp-qa-appwide-arm", str(selected), TOKEN],
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, encoding="utf-8", env=env)
            ready = queue.Queue(maxsize=1)
            threading.Thread(target=lambda: ready.put(guard.stdout.readline()), daemon=True).start()
            try:
                line = ready.get(timeout=10)
            except queue.Empty:
                raise RuntimeError("AppId-wide BFE guard readiness timed out") from None
            assert line and guard.poll() is None
            started = json.loads(line)
            assert started["ok"] and started["persistent"] and started["bfe_readback"]
            assert started["appid_only_no_port_filter"] and started["ipv4_ipv6"]
            assert started["system_rescue_prearmed"] and not started["protected_fail_closed"]
            checks["two_persistent_appwide_filters"] = status(agent) == (True, True, True)
            for server in servers:
                probe(server, selected, sibling, False, checks, "guarded")
            assert guard.poll() is None
            guard.kill()
            guard.wait(timeout=5)
            guard = None
            checks["guard_process_forced_termination"] = True
            checks["filters_survived_crash"] = status(agent) == (True, True, True)
            for server in servers:
                probe(server, selected, sibling, False, checks, "after_crash")
            cleanup(agent)
            cleaned = True
            checks["exact_cleanup"] = True
            for server in servers:
                probe(server, selected, sibling, True, checks, "after_cleanup")
            assert all(checks.values())
            report["passed"] = True
    except Exception as exc:
        report["error_class"] = type(exc).__name__
        raise
    finally:
        if guard:
            guard.kill()
            guard.wait(timeout=5)
        # If cleanup is not verified, leave the independent SYSTEM task intact.
        if rescue_armed:
            if not cleaned:
                cleanup(agent)
            remove_rescue()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
