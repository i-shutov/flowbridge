#!/usr/bin/env python3
"""Read-only candidate verification and allow-listed packaging. Never install NDISRD."""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import zipfile


class Adapters(C.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [("count", C.c_uint32), ("names", (C.c_ubyte * 256) * 32),
                ("handles", C.c_uint64 * 32), ("media", C.c_uint32 * 32),
                ("macs", (C.c_ubyte * 6) * 32), ("mtus", C.c_uint16 * 32)]


class Mode(C.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [("handle", C.c_uint64), ("flags", C.c_uint32)]


class Packet(C.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [("links", C.c_uint64 * 2), ("direction", C.c_uint32),
                ("length", C.c_uint32), ("flags", C.c_uint32), ("vlan", C.c_uint32),
                ("filter_id", C.c_uint32), ("reserved", C.c_uint32 * 4),
                ("data", C.c_ubyte * 9014)]


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_sha() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()


def agent_json(agent: pathlib.Path, *args: str, success: bool = True) -> dict:
    run = subprocess.run([str(agent.resolve()), *args], text=True, encoding="utf-8",
                         capture_output=True, timeout=15, check=False)
    if (run.returncode == 0) != success:
        raise RuntimeError(f"Unexpected agent exit code {run.returncode} for {args[0]}")
    result = json.loads(run.stdout)
    if not isinstance(result, dict):
        raise ValueError("Agent reply is not an object")
    return result


def verify(agent: pathlib.Path, output: pathlib.Path) -> None:
    cap = agent_json(agent, "capabilities")
    expected = {"adapters": C.sizeof(Adapters), "mode": C.sizeof(Mode),
                "request": 16, "packet_header": Packet.data.offset,
                "packet_capacity": C.sizeof(Packet)}
    # Independent ctypes model, not the Rust codec's offsets.
    if (Adapters.handles.offset, Adapters.media.offset, Adapters.macs.offset, Adapters.mtus.offset) != (8196, 8452, 8580, 8772):
        raise AssertionError("Independent x64 pack(1) fixture is inconsistent")
    if cap["abi"] != expected:
        raise AssertionError(f"ABI differs from independent packed fixture: {cap['abi']}")
    for flag in ("native_owner_binding_accepted", "protected_redirect_available", "dns_leak_free", "release_accepted", "vendor_driver_bundled", "custom_wfp_required", "proxifyre_required"):
        if cap[flag] is not False:
            raise AssertionError(f"Forbidden acceptance/capability claim: {flag}")
    for request in (
        {"adapter_name": "invalid", "duration_ms": 1, "consent": ""},
        {"adapter_name": "invalid", "duration_ms": 60001, "consent": "LISTEN_ONLY"},
        {"adapter_name": "invalid", "duration_ms": 1, "consent": "LISTEN_ONLY", "protected": True},
    ):
        agent_json(agent, "lab", json.dumps(request), success=False)
    agent_json(agent, "protected", success=False)
    status = agent_json(agent, "status")  # read only; no mode-changing request
    report = {
        "passed": True, "test_kind": "read_only_agent_cli_and_independent_abi",
        "source_commit": git_sha(), "pr_head_sha": os.environ.get("PR_HEAD_SHA"),
        "platform": platform.platform(), "agent_sha256": digest(agent), "abi": expected,
        "driver_probe_supported": status["driver"].get("supported", False),
        "driver_mode_changed": False, "packet_capture_tested": False,
        "protected_redirect_tested": False, "dns_leaks_tested": False,
        "win10_11_native_acceptance": False, "release_accepted": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


def package(agent: pathlib.Path, cli: pathlib.Path, output: pathlib.Path) -> None:
    if not agent.is_file() or not cli.is_file():
        raise FileNotFoundError("Build both original Rust binaries before packaging")
    suffix = ".exe" if os.name == "nt" else ""
    payload = {"flowbridge-agent" + suffix: agent.read_bytes(), "flowbridge" + suffix: cli.read_bytes(),
               "README.md": pathlib.Path("docs/qa/RUST_CAPTURE_INTEGRATION_CANDIDATE.md").read_bytes()}
    manifest = {
        "schema": 1, "kind": "integration_candidate_NOT_RELEASE", "source_commit": git_sha(),
        "pr_head_sha": os.environ.get("PR_HEAD_SHA"), "platform": platform.platform(),
        "payload_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in payload.items()},
        "legacy_cpp_wfp_helper_included": False, "vendor_binary_included": False,
        "protected_mode_available": False, "win10_11_accepted": False, "release_accepted": False,
    }
    payload["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in payload.items():
            archive.writestr(name, data)
    with zipfile.ZipFile(output) as archive:
        if set(archive.namelist()) != set(payload):
            raise AssertionError("Unexpected payload file")
        for name, expected in manifest["payload_sha256"].items():
            if hashlib.sha256(archive.read(name)).hexdigest() != expected:
                raise AssertionError("Packaged bytes differ from original Rust build")
    output.with_suffix(output.suffix + ".sha256").write_text(f"{digest(output)}  {output.name}\n", encoding="utf-8")
    print(json.dumps({"package": output.name, "sha256": digest(output), "source_commit": git_sha()}))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["verify", "package"])
    parser.add_argument("--agent", type=pathlib.Path, required=True)
    parser.add_argument("--cli", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.operation == "verify":
        verify(args.agent, args.output)
    else:
        if args.cli is None:
            parser.error("package requires --cli")
        package(args.agent, args.cli, args.output)


if __name__ == "__main__":
    main()
