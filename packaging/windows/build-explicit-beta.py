#!/usr/bin/env python3
"""Build a separately namespaced, explicit-SOCKS-only Windows engineering candidate.

This builder NEVER invokes the WFP/helper build; it refuses any driver/helper
in the payload and requires the GUI to have the compile-time beta scope gate.
It creates an unsigned QA installer, not the production v0.3.0-beta.1 release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE_NAME = "FlowBridge-0.2.0-explicit-candidate-windows-x64-setup.exe"
BUILD_DIR = ROOT / "build" / "windows-explicit-beta"
STAGE = ROOT / "build" / "explicit-beta-payload"
OUTPUT = ROOT / "artifacts" / CANDIDATE_NAME
REPORT = ROOT / "build" / "verification" / "explicit-beta-package.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args: list[str]) -> str:
    proc = subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=900)
    print("+", " ".join(args), flush=True)
    print(proc.stdout, flush=True)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, flush=True)
    return proc.stdout.strip()


def pe_machine(path: Path, *, installer: bool = False) -> str:
    data = path.read_bytes()
    if len(data) < 0x60 or data[:2] != b"MZ":
        raise RuntimeError(f"Not a PE executable: {path.name}")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset < 64 or offset + 24 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        raise RuntimeError(f"Malformed PE header: {path.name}")
    machine = struct.unpack_from("<H", data, offset + 4)[0]
    allowed = {0x014C, 0x8664} if installer else {0x8664}
    if machine not in allowed:
        raise RuntimeError(f"Wrong PE machine for {path.name}: {machine:#x}")
    return f"0x{machine:04x}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true",
                        help="Stage binaries already built with FLOWBRIDGE_EXPLICIT_BETA_ONLY=ON")
    args = parser.parse_args()
    if sys.platform != "win32":
        raise RuntimeError("This Windows x64 candidate builder requires native Windows")
    source_commit = run(["git", "rev-parse", "HEAD"]).strip()
    if len(source_commit) != 40 or any(c not in "0123456789abcdef" for c in source_commit):
        raise RuntimeError("Cannot verify exact source commit")
    if not args.skip_build:
        run(["cargo", "build", "--locked", "--release", "-j", "2",
             "-p", "flowbridge-cli", "-p", "flowbridge-ffi"])
        ffi = (ROOT / "target/release/flowbridge_ffi.dll.lib").resolve()
        run(["cmake", "-S", "native/windows", "-B", str(BUILD_DIR),
             "-A", "x64", "-DFLOWBRIDGE_EXPLICIT_BETA_ONLY=ON",
             "-DFLOWBRIDGE_BUILD_NATIVE_TESTS=ON",
             f"-DFLOWBRIDGE_FFI_LIBRARY={ffi}"])
        run(["cmake", "--build", str(BUILD_DIR), "--config", "Release", "--parallel", "2"])
    cache = BUILD_DIR / "CMakeCache.txt"
    if not cache.is_file() or "FLOWBRIDGE_EXPLICIT_BETA_ONLY:BOOL=ON" not in cache.read_text(
            encoding="utf-8", errors="replace"):
        raise RuntimeError("Explicit-only CMake compile flag is NOT proven ON")
    gui = BUILD_DIR / "Release/FlowBridge.exe"
    cli = ROOT / "target/release/flowbridge.exe"
    ffi_dll = ROOT / "target/release/flowbridge_ffi.dll"
    files = [
        (gui, "FlowBridge.exe"),
        (cli, "flowbridge-cli.exe"),
        (ffi_dll, "flowbridge_ffi.dll"),
        (ROOT / "LICENSE", "LICENSE"),
        (ROOT / "packaging/windows/README-EXPLICIT-BETA.txt", "README.txt"),
        (ROOT / "third_party/nlohmann/LICENSE.MIT", "licenses/nlohmann-json-LICENSE.MIT"),
        (ROOT / "third_party/THIRD_PARTY_NOTICES.txt", "licenses/THIRD_PARTY_NOTICES.txt"),
        (ROOT / "resources/presets.json", "resources/presets.json"),
    ]
    files.extend((ROOT / "examples" / name, "examples/" + name)
                 for name in ("direct.json", "ssh-socks.json", "chain.json"))
    if STAGE.exists() and any(STAGE.iterdir()):
        raise RuntimeError("Explicit beta staging directory must start empty")
    STAGE.mkdir(parents=True, exist_ok=True)
    entries = []
    for src, rel in files:
        if not src.is_file() or src.is_symlink():
            raise RuntimeError(f"Missing regular source artifact: {src}")
        if any(tag in rel.lower() for tag in ("capture", "wfp", ".sys", ".inf", "ndisrd")):
            raise RuntimeError(f"Protected mode component forbidden in explicit beta: {rel}")
        dst = STAGE / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        machine = pe_machine(dst) if dst.suffix.lower() in (".exe", ".dll") else None
        entries.append({"path": rel, "bytes": dst.stat().st_size,
                        "sha256": digest(dst), "pe_machine": machine})
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT.exists():
        raise RuntimeError("Refusing to silently replace an existing installer")
    nsis = shutil.which("makensis.exe")
    if not nsis:
        for base in (os.environ.get("ProgramFiles(x86)", ""), os.environ.get("ProgramFiles", "")):
            candidate = Path(base) / "NSIS" / "makensis.exe"
            if candidate.is_file():
                nsis = str(candidate)
                break
    if not nsis:
        raise RuntimeError("Verified portable NSIS was not available; no installer produced")
    run([nsis, "/INPUTCHARSET", "UTF8", "/DPAYLOAD_DIR=" + str(STAGE),
         "/DOUTPUT_FILE=" + str(OUTPUT), "packaging/windows/FlowBridgeExplicitBeta.nsi"])
    installer_arch = pe_machine(OUTPUT, installer=True)
    report = {
        "schema": "flowbridge-explicit-beta-windows-qa-package-v1",
        "candidate": "0.2.0-explicit-candidate",
        "source_sha": source_commit,
        "installer": str(OUTPUT),
        "installer_sha256": digest(OUTPUT),
        "installer_bytes": OUTPUT.stat().st_size,
        "bootstrapper_pe_machine": installer_arch,
        "payload": entries,
        "signed": False,
        "publisher_release_approved": False,
        "explicit_socks_only": True,
        "gui_protected_ui_compiled_disabled": True,
        "driver_included": False,
        "capture_helper_included": False,
        "system_service_included": False,
        "profile_namespace": "FlowBridgeExplicitBeta",
        "uninstall_registration": "FlowBridgeExplicitBeta",
        "system_dns_or_proxy_mutated": False,
        "app_specific_interception": False,
        "udp_or_quic_proxied": False,
        "wfp_native_gate": "NO_GO",
        "independent_reviewer_passed": False,
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    (OUTPUT.parent / (OUTPUT.name + ".sha256")).write_text(
        report["installer_sha256"] + "  " + OUTPUT.name + "\n", encoding="ascii")
    print(json.dumps({k: v for k, v in report.items() if k != "payload"},
                     indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
