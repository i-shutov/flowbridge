#!/usr/bin/env python3
"""Read-only PE import inventory of exact frozen Windows beta.2; no execution."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

SOURCE = "86583a1a0487b9d383c0122b24558e620bde5b9c"
FILES = {
    "FlowBridge.exe": ("build/explicit-beta-payload/FlowBridge.exe",
        "0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e"),
    "flowbridge_ffi.dll": ("build/explicit-beta-payload/flowbridge_ffi.dll",
        "23b62d54a89feea53331f3ac68fe7c3d348ca99ed72d816f3dcfbc94ef3fd2b4"),
    "FlowBridge-0.3.0-beta.2-windows-x64-setup.exe": (
        "artifacts/FlowBridge-0.3.0-beta.2-windows-x64-setup.exe",
        "0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4")
}
ALLOWED = {"advapi32.dll","comctl32.dll","comdlg32.dll","gdi32.dll",
           "kernel32.dll","shell32.dll","user32.dll","flowbridge_ffi.dll",
           "ntdll.dll","ole32.dll","ws2_32.dll",
           "api-ms-win-core-synch-l1-2-0.dll","bcryptprimitives.dll","iphlpapi.dll"}
IMPORT = re.compile(r"^\s*DLL Name:\s*([^\s]+)\s*$", re.M)

def parse_imports(text: str) -> list[str]:
    libs=sorted({name.lower() for name in IMPORT.findall(text)})
    if not libs:
        raise ValueError("no_pe_imports")
    if any(name not in ALLOWED for name in libs):
        raise ValueError("unexpected_dynamic_import")
    return libs

def examine(root: Path) -> dict:
    records={}
    for label, (relative, required_sha) in FILES.items():
        file=root / relative
        if not file.is_file() or file.is_symlink():
            raise ValueError("original_artifact_missing")
        if hashlib.sha256(file.read_bytes()).hexdigest() != required_sha:
            raise ValueError("exact_binary_sha_mismatch")
        cmd=subprocess.run(["objdump","-p",str(file)],capture_output=True,text=True,
                           check=True,timeout=30)
        records[label]={"sha256":required_sha,
                        "direct_imported_dll_names":parse_imports(cmd.stdout)}
    return {"schema":"flowbridge-win10-beta2-original-pe-import-v1",
            "candidate_source_sha":SOURCE,
            "result":"DIRECT_PE_IMPORTS_TECHNICAL_PASS",
            "files":records,
            "direct_vcruntime_or_msvcp_imports_observed":False,
            "recursive_dll_dependency_and_linkage_proven":False,
            "native_sdk_runtime_redistribution_legal_review_passed":False,
            "a5_accepted":False,"a6_accepted":False,"release_accepted":False}

def main()->int:
    cli=argparse.ArgumentParser()
    cli.add_argument("--original-windows-artifact-dir",required=True,type=Path)
    cli.add_argument("--output",required=True,type=Path)
    args=cli.parse_args()
    report={"result":"BLOCKED","a5_accepted":False,"a6_accepted":False,
            "release_accepted":False,"error_code":None}
    rc=1
    try:
        report=examine(args.original_windows_artifact_dir)
        rc=0
    except (ValueError,OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
        report["error_code"]=str(e) if isinstance(e,ValueError) else "pe_inspection_failed"
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(report["result"] + ((" "+report["error_code"]) if rc else ""))
    return rc

if __name__=="__main__":
    raise SystemExit(main())
