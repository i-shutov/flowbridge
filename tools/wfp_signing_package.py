#!/usr/bin/env python3
"""Prepare and audit UNSIGNED WFP signing inputs; never sign or install a driver.

The output CAB is an input to an authorized EV/Partner Center submission,
not an installable driver or evidence of a Microsoft signature.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

DRIVER_FILES = ("FlowBridgeWfp.inf", "FlowBridgeWfp.sys", "FlowBridgeWfp.cat", "FlowBridgeWfp.pdb")
CAB_NAME = "FlowBridgeWfp-UNSIGNED-input.cab"
MAX_FILE_BYTES = 64 * 1024 * 1024


class PreflightError(ValueError):
    """The candidate package is incomplete or unsafe to package."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise PreflightError(f"Required regular file is missing (or a symlink): {path}")
    size = path.stat().st_size
    if size == 0 or size > MAX_FILE_BYTES:
        raise PreflightError(f"Required file has an invalid size: {path}")


def locate(directory: Path, filename: str) -> Path:
    if not directory.is_dir() or directory.is_symlink():
        raise PreflightError(f"Expected WDK package directory: {directory}")
    matches = [p for p in directory.iterdir() if p.name.casefold() == filename.casefold()]
    if len(matches) != 1:
        raise PreflightError(f"Expected exactly one {filename} in {directory}")
    require_file(matches[0])
    return matches[0]


def validate_inf(inf_path: Path) -> None:
    raw = inf_path.read_bytes()
    try:
        content = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PreflightError("Driver INF has unsupported character encoding") from exc
    lines = [line.split(";", 1)[0].strip() for line in content.splitlines()]
    pairs: dict[str, str] = {}
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            pairs[key.strip().casefold()] = value.strip().strip('"').casefold()
    required = {
        "signature": "$windows nt$",
        "catalogfile": "flowbridgewfp.cat",
        "servicetype": "1",
        "starttype": "3",
        "pnplockdown": "1",
    }
    for field, expected in required.items():
        if pairs.get(field) != expected:
            raise PreflightError(f"Driver INF must contain {field}={expected}")
    if pairs.get("servicebinary", "").replace("/", "\\") != r"%13%\flowbridgewfp.sys":
        raise PreflightError("INF ServiceBinary does not reference FlowBridgeWfp.sys")
    if not pairs.get("driverver"):
        raise PreflightError("Stamped WDK DriverVer is missing")


def input_files(package_dir: Path, pdb_path: Path) -> dict[str, Path]:
    paths = {name: locate(package_dir, name) for name in DRIVER_FILES[:-1]}
    if pdb_path.name.casefold() != DRIVER_FILES[-1].casefold():
        raise PreflightError("Expected FlowBridgeWfp.pdb from the same WDK build")
    require_file(pdb_path)
    paths[DRIVER_FILES[-1]] = pdb_path
    with paths["FlowBridgeWfp.sys"].open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise PreflightError("WDK driver is not a PE image")
    validate_inf(paths["FlowBridgeWfp.inf"])
    return paths


def write_ddf(staging: Path, target: Path) -> Path:
    # Windows paths are absolute; cabinet contents are limited to the four
    # explicitly allowlisted files under a single, fixed driver subdirectory.
    source_paths = [staging / name for name in DRIVER_FILES]
    if any('"' in str(path) or "\n" in str(path) or "\r" in str(path) for path in source_paths):
        raise PreflightError("Invalid character in local package path")
    lines = [
        ".OPTION EXPLICIT",
        ".Set CabinetFileCountThreshold=0",
        ".Set FolderFileCountThreshold=0",
        ".Set FolderSizeThreshold=0",
        ".Set MaxCabinetSize=0",
        ".Set MaxDiskFileCount=0",
        ".Set MaxDiskSize=0",
        ".Set CompressionType=MSZIP",
        ".Set Cabinet=on",
        ".Set Compress=on",
        f".Set CabinetNameTemplate={CAB_NAME}",
        ".Set DestinationDir=FlowBridgeWfp",
    ]
    lines.extend(f'"{source}" "{source.name}"' for source in source_paths)
    target.write_text("\r\n".join(lines) + "\r\n", encoding="ascii")
    return target


def make_cab(out_dir: Path, ddf: Path, hashes: dict[str, dict[str, str | int]]) -> Path:
    # No secrets, certificate stores, Windows boot settings, or driver installs.
    subprocess.run(["makecab.exe", "/F", str(ddf)], cwd=out_dir, check=True)
    found = [p for p in out_dir.rglob(CAB_NAME) if p.is_file() and not p.is_symlink()]
    if len(found) != 1:
        raise PreflightError("MakeCAB did not produce exactly one expected CAB")
    cab = found[0]
    with cab.open("rb") as stream:
        if stream.read(4) != b"MSCF":
            raise PreflightError("MakeCAB output is not a CAB file")
    extraction = out_dir / "cab-verify"
    extraction.mkdir(exist_ok=False)
    subprocess.run(["expand.exe", "-F:*", str(cab), str(extraction)], cwd=out_dir, check=True)
    extracted = [p for p in extraction.rglob("*") if p.is_file()]
    if len(extracted) != len(DRIVER_FILES):
        raise PreflightError("CAB does not contain exactly four driver files")
    for name in DRIVER_FILES:
        found_file = [p for p in extracted if p.name.casefold() == name.casefold()]
        if len(found_file) != 1 or sha256(found_file[0]) != hashes[name]["sha256"]:
            raise PreflightError(f"CAB round-trip failed for {name}")
    shutil.rmtree(extraction)
    return cab


def prepare(package_dir: Path, pdb_path: Path, out_dir: Path, source_sha: str, *, create_cab: bool) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise PreflightError("Full 40-character source SHA is required")
    paths = input_files(package_dir, pdb_path)
    if out_dir.exists():
        raise PreflightError("Signing output directory already exists; refusing stale mixed artifacts")
    hashes = {
        name: {"sha256": sha256(path), "size_bytes": path.stat().st_size}
        for name, path in paths.items()
    }
    staging = out_dir / "staging" / "FlowBridgeWfp"
    staging.mkdir(parents=True, exist_ok=False)
    for name, source in paths.items():
        dest = staging / name
        shutil.copyfile(source, dest)
        if sha256(dest) != hashes[name]["sha256"]:
            raise PreflightError(f"Staged {name} changed unexpectedly")
    ddf = write_ddf(staging.resolve(), out_dir / "FlowBridgeWfp.ddf")
    cab = make_cab(out_dir.resolve(), ddf.resolve(), hashes) if create_cab else None
    report = {
        "schema_version": 1,
        "source_sha": source_sha,
        "scope": "unsigned_WDK_build_input_only",
        "wdk_package_inputs_checked": True,
        "cabinet_generated_and_byte_verified": cab is not None,
        "signature_status": "NOT_VERIFIED",
        "microsoft_hardware_signature_verified": False,
        "driver_installed_or_loaded": False,
        "wfp_runtime_acceptance": False,
        "server_2025_requirement": "Microsoft HLK/WHCP signed driver; desktop attestation is insufficient",
        "files": hashes,
        "cabinet": None if cab is None else {"name": cab.name, "sha256": sha256(cab), "size_bytes": cab.stat().st_size},
    }
    (out_dir / "wfp-signing-input.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", type=Path, required=True)
    parser.add_argument("--pdb", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--no-cab", action="store_true", help="Unit-test fixture only; CI must create and verify the CAB")
    args = parser.parse_args()
    result = prepare(args.package_dir, args.pdb, args.out_dir, args.commit, create_cab=not args.no_cab)
    print(json.dumps({"source_sha": result["source_sha"], "scope": result["scope"],
                      "cabinet_generated_and_byte_verified": result["cabinet_generated_and_byte_verified"]}))


if __name__ == "__main__":
    main()
