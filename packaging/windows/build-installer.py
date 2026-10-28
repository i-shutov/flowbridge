#!/usr/bin/env python3
"""Build and stage a real Windows x64 GUI, Rust DLL/CLI and NSIS installer.

Windows: run in an x64 MSVC developer shell with Rust, CMake and NSIS in PATH.
Linux: install MinGW-w64, Ninja, NSIS and Rust x86_64-pc-windows-gnu target.
--skip-build stages existing binaries; it does not waive native release tests.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]


def run(command):
    print("+ " + " ".join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), cwd=ROOT, check=True)


def check_pe(path, allowed_machines):
    """Validate a PE header without trusting offsets from a malformed file."""
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError(f"Not a Windows PE file: {path.name}")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset < 64 or offset + 24 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        raise ValueError(f"Invalid Windows PE header: {path.name}")
    machine = struct.unpack_from("<H", data, offset + 4)[0]
    if machine not in allowed_machines:
        raise ValueError(f"Unexpected PE machine 0x{machine:04x}: {path.name}")
    return machine


def check_pe64(path):
    return check_pe(path, {0x8664})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    windows = sys.platform == "win32"
    target = [] if windows else ["--target", "x86_64-pc-windows-gnu"]
    rust = ROOT / "target" / ("release" if windows else "x86_64-pc-windows-gnu/release")
    cmake = ROOT / "build" / ("windows" if windows else "windows-gnu")
    gui = cmake / ("Release/FlowBridge.exe" if windows else "FlowBridge.exe")
    ffi = rust / ("flowbridge_ffi.dll.lib" if windows else "libflowbridge_ffi.dll.a")
    if not args.skip_build:
        run(["cargo", "build", "--locked", "--release", *target, "-p", "flowbridge-ffi", "-p", "flowbridge-cli"])
        configure = ["cmake", "-S", "native/windows", "-B", cmake, f"-DFLOWBRIDGE_FFI_LIBRARY={ffi}"]
        if windows:
            configure += ["-A", "x64"]
        else:
            configure += ["-G", "Ninja", "-DCMAKE_SYSTEM_NAME=Windows", "-DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++", "-DCMAKE_BUILD_TYPE=Release"]
        run(configure)
        run(["cmake", "--build", cmake, "--config", "Release", "--target", "FlowBridge"])
    payload = ROOT / "build/payload"
    files = [(gui, "FlowBridge.exe"), (rust / "flowbridge.exe", "flowbridge-cli.exe"),
             (rust / "flowbridge_ffi.dll", "flowbridge_ffi.dll"), (ROOT / "LICENSE", "LICENSE"),
             (ROOT / "packaging/windows/README.txt", "README.txt"),
             (ROOT / "third_party/nlohmann/LICENSE.MIT", "licenses/nlohmann-json-LICENSE.MIT"),
             (ROOT / "third_party/THIRD_PARTY_NOTICES.txt", "licenses/THIRD_PARTY_NOTICES.txt"),
             (ROOT / "resources/presets.json", "resources/presets.json")]
    files += [(ROOT / "examples" / name, "examples/" + name) for name in ("direct.json", "ssh-socks.json", "chain.json")]
    entries = []
    for source, relative in files:
        if not source.is_file() or source.is_symlink():
            raise FileNotFoundError(source)
        destination = payload / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        if destination.suffix.lower() in (".exe", ".dll"):
            check_pe64(destination)
        entries.append({"path": relative, "bytes": destination.stat().st_size,
                        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()})
    output = ROOT.parent / "artifacts"
    output.mkdir(exist_ok=True)
    installer = output / f"FlowBridge-{VERSION}-windows-x64-setup.exe"
    nsis = shutil.which("makensis")
    if not nsis and windows:
        for base in [os.environ.get("ProgramFiles(x86)", ""), os.environ.get("ProgramFiles", "")]:
            candidate = pathlib.Path(base) / "NSIS/makensis.exe"
            if candidate.is_file():
                nsis = str(candidate)
                break
    if not nsis:
        raise RuntimeError("NSIS makensis is required; staging succeeded but no installer was created")
    flag = "/D" if windows else "-D"
    run([nsis, "/INPUTCHARSET" if windows else "-INPUTCHARSET", "UTF8", f"{flag}PAYLOAD_DIR={payload}", f"{flag}OUTPUT_FILE={installer}", "packaging/windows/FlowBridge.nsi"])
    # Bootstrapper architecture is independent of the installed application.
    installer_machine = check_pe(installer, {0x014C, 0x8664})
    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    (output / (installer.name + ".sha256")).write_text(f"{digest}  {installer.name}\n")
    report = {"version": VERSION, "installer": str(installer), "bytes": installer.stat().st_size,
              "sha256": digest, "signed": False, "bootstrapper_machine": f"0x{installer_machine:04x}", "payload_architecture": "x86_64", "mode": "explicit_socks5_with_optional_managed_ssh", "payload": entries}
    (ROOT / "docs/verification/windows-package.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "payload"}, indent=2))


if __name__ == "__main__":
    main()
