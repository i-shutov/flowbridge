#!/usr/bin/env python3
"""Build an UNSIGNED, Rust-only per-user Windows SSH/SOCKS candidate installer.

The sole input is the exact GitHub Actions four-file Rust candidate archive.
Do not promote this experimental installer to a Windows 10/11 acceptance,
protected-mode driver installer, GUI package, or release artifact.
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
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {"flowbridge.exe", "flowbridge-agent.exe", "flowbridge-panel.exe", "README.md", "manifest.json"}
BINARY = {"flowbridge.exe", "flowbridge-agent.exe", "flowbridge-panel.exe"}
MAX_MEMBER = 32 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pe_amd64(data: bytes) -> None:
    require(len(data) >= 0x40 and data[:2] == b"MZ", "Missing DOS PE header")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    require(0x40 <= offset <= len(data) - 26 and data[offset:offset + 4] == b"PE\0\0",
            "Malformed PE header")
    require(struct.unpack_from("<H", data, offset + 4)[0] == 0x8664,
            "Candidate payload must be x64 AMD64")
    require(struct.unpack_from("<H", data, offset + 24)[0] == 0x20B,
            "Candidate payload must be PE32+")


def verify_archive(path: Path, head: str, merge: str) -> tuple[dict, dict[str, bytes]]:
    require(path.is_file() and not path.is_symlink(), "Candidate archive missing or linked")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) == len(EXPECTED) and {x.filename for x in entries} == EXPECTED,
                "Candidate archive must contain only the four original Rust files")
        require(all(not x.is_dir() and 0 < x.file_size <= MAX_MEMBER
                    and (x.external_attr >> 16) & 0o170000 != 0o120000
                    for x in entries), "Unsafe archive entry, symlink or size")
        payload = {name: archive.read(name) for name in EXPECTED}
        require(archive.testzip() is None, "Corrupt candidate archive CRC")
    manifest = json.loads(payload["manifest.json"])
    require(isinstance(manifest, dict) and manifest.get("schema") == 1
            and manifest.get("kind") == "integration_candidate_NOT_RELEASE",
            "Wrong Rust candidate manifest kind")
    require(manifest.get("source_commit") == merge and manifest.get("pr_head_sha") == head,
            "Candidate source merge/PR head does not match checked out workflow")
    require(manifest.get("payload_sha256") == {
        name: sha256(payload[name]) for name in EXPECTED - {"manifest.json"}},
        "Candidate manifest payload digest mismatch")
    for flag in ("legacy_cpp_wfp_helper_included", "vendor_binary_included",
                 "protected_mode_available", "win10_11_accepted", "release_accepted"):
        require(manifest.get(flag) is False, f"Unsafe claimed capability: {flag}")
    for name in BINARY:
        pe_amd64(payload[name])
    return manifest, payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--qa-abort-stage", choices=("after-cli", "after-uninstaller"))
    args = parser.parse_args()
    require(sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_OS") == "Windows",
            "Installer builder restricted to disposable hosted Windows CI")
    merge = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                    text=True).strip()
    head = os.environ.get("PR_HEAD_SHA", "")
    require(len(head) == 40 and all(c in "0123456789abcdef" for c in head),
            "Exact PR head SHA is required")
    manifest, payload = verify_archive(args.candidate, head, merge)
    nsis = shutil.which("makensis")
    if nsis is None:
        bases = [os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")]
        nsis = next((str(Path(x) / "NSIS" / "makensis.exe") for x in bases
                     if x and (Path(x) / "NSIS" / "makensis.exe").is_file()), None)
    require(nsis is not None, "makensis unavailable (no silent NSIS fallback)")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    # Original Rust panel only, no vendor binary, private key or legacy GUI.
    with tempfile.TemporaryDirectory(prefix="flowbridge-rust-installer-") as staging:
        stage = Path(staging)
        for name, data in payload.items():
            (stage / name).write_bytes(data)
        license_data = (ROOT / "LICENSE").read_bytes()
        (stage / "LICENSE").write_bytes(license_data)
        cmd = [nsis, "/INPUTCHARSET", "UTF8",
               f"/DPAYLOAD_DIR={stage}", f"/DOUTPUT_FILE={args.output.resolve()}",
               str(ROOT / "packaging/windows/FlowBridgeRustCandidate.nsi")]
        if args.qa_abort_stage is not None:
            require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
                    "Fault-injected installer is restricted to disposable hosted Windows")
            define = ("QA_ABORT_AFTER_CLI" if args.qa_abort_stage == "after-cli"
                      else "QA_ABORT_AFTER_UNINSTALLER")
            cmd.insert(-1, f"/D{define}=1")
        subprocess.run(cmd, check=True, cwd=ROOT, timeout=120)
    installed = {name: sha256(payload[name]) for name in EXPECTED}
    installed["LICENSE"] = sha256(license_data)
    require(args.output.is_file(), "NSIS produced no installer")
    pe = args.output.read_bytes()
    require(len(pe) > 4096 and pe[:2] == b"MZ", "Invalid NSIS executable")
    result = {
        "kind": ("unsigned_user_owned_rust_ssh_socks_candidate_installer_NOT_RELEASE"
                 if args.qa_abort_stage is None else
                 "qa_fault_injected_rust_candidate_installer_NEVER_RELEASE"),
        "qa_fault_fixture": args.qa_abort_stage is not None,
        "qa_abort_stage": args.qa_abort_stage,
        "passed": True, "source_merge_sha": merge, "pr_head_sha": head,
        "candidate_archive_sha256": sha256(args.candidate.read_bytes()),
        "candidate_source_manifest_sha256": sha256(payload["manifest.json"]),
        "installer_sha256": sha256(pe), "installer_bytes": len(pe),
        "payload_sha256": installed, "signed": False,
        "native_driver_installed_or_modified": False,
        "scm_service_installed_or_modified": False,
        "contains_legacy_cpp_wfp": False, "contains_vendor_binary": False,
        "includes_gui": True, "gui_scope": "same_user_explicit_ssh_socks_only", "native_packet_pid_proof": False,
        "protected_fail_closed": False, "dns_leak_free": False,
        "windows_10_11_accepted": False, "release_accepted": False,
    }
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "payload_sha256"}))


if __name__ == "__main__":
    main()
