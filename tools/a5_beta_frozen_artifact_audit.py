#!/usr/bin/env python3
"""A5 frozen-artifact provenance and dependency inventory audit.

Independent, byte-only inspection of the ORIGINAL FlowBridge 0.3.0-beta.1
GitHub Actions candidate kit. No install, binary execution, signing, vendor
requests, native runtime inference or license-selection on owner's behalf.

Successful technical inventory audit must NEVER set A5/release accepted.
"""
from __future__ import annotations
import argparse
from io import BytesIO
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import zipfile

SOURCE = "f5ecd48d8f81c594f755a55e7969b57d20903020"
RUN = "43407093536"
VERSION = "0.3.0-beta.1"
KIT = "FlowBridge-0.3.0-beta.1-candidate-f5ecd48d8f81.zip"
KIT_SHA256 = "4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8"
INSTALLERS = {
    "windows/FlowBridge-0.3.0-beta.1-windows-x64-setup.exe":
        "74ff309d2e8ae115083bed9c5d4f233fd02dc841a8084a22912f3430c1e4b504",
    "macos/FlowBridge-0.3.0-beta.1-macOS-universal-explicit-beta.pkg":
        "7eb645e227442ba5a2d12bc1b9c5853212baf8a3d28e7215640f0e3e2ec0453c",
}
TOTAL_FILE_BYTES_LIMIT = 50_000_000
HEX = re.compile(r"[0-9a-f]{64}\Z")


class AuditError(Exception):
    pass


def check(value: bool, error: str) -> None:
    if not value:
        raise AuditError(error)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_members(archive: zipfile.ZipFile, *, max_files: int = 256) -> dict[str, zipfile.ZipInfo]:
    result = {}
    folded = set()
    total = 0
    for item in archive.infolist():
        path = PurePosixPath(item.filename)
        # ZIP paths must not alias, escape, use platform-specific separators
        # or smuggle symlink files into a candidate.
        check(not item.is_dir() and item.filename == path.as_posix() and
              not item.filename.startswith("/") and not item.filename.startswith("./") and
              "\\" not in item.filename and
              all(part not in ("", ".", "..") for part in item.filename.split("/")),
              "unsafe_zip_path")
        unix_mode = item.external_attr >> 16
        check(unix_mode & 0o170000 != 0o120000, "zip_symlink_disallowed")
        low = item.filename.casefold()
        check(low not in folded, "zip_duplicate_casefold")
        folded.add(low)
        total += item.file_size
        check(total <= TOTAL_FILE_BYTES_LIMIT, "zip_uncompressed_size_exceeded")
        check(item.file_size <= TOTAL_FILE_BYTES_LIMIT, "zip_member_too_large")
        result[item.filename] = item
    check(0 < len(result) <= max_files, "zip_entry_count_invalid")
    return result


def load_json(data: bytes, code: str) -> dict:
    check(len(data) <= 1_500_000, code + "_oversized")
    try:
        obj = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuditError(code + "_invalid") from exc
    check(type(obj) is dict, code + "_not_object")
    return obj


def verify_bom(platform: str, files: dict[str, bytes]) -> dict:
    base = platform + "/"
    meta = load_json(files[base + "BUILD-METADATA.json"], platform + "_metadata")
    bom = load_json(files[base + "SBOM.cdx.json"], platform + "_sbom")
    notices = files[base + "THIRD_PARTY_NOTICES.txt"]
    check(meta.get("schema") == "flowbridge-explicit-beta-build-metadata-v1" and
          meta.get("source_sha") == SOURCE and meta.get("version") == VERSION and
          meta.get("platform") == platform and meta.get("explicit_socks_only") is True and
          meta.get("driver_included") is False and
          meta.get("system_extension_included") is False, platform + "_identity_or_scope")
    check(meta.get("publisher_release_approved") is False and
          meta.get("independent_license_review_passed") is False and
          meta.get("binary_linkage_reviewed") is False and
          meta.get("vulnerability_audit_performed") is False,
          platform + "_unsupported_review_claim")
    check(sha(files[base+"SBOM.cdx.json"])==meta.get("sbom_sha256") and
          sha(notices)==meta.get("notices_sha256"), platform + "_inventory_digest_mismatch")
    check(bom.get("bomFormat")=="CycloneDX" and bom.get("specVersion")=="1.5" and
          bom.get("version")==1, platform + "_sbom_contract")
    check(bom.get("metadata", {}).get("component", {}).get("version")==VERSION,
          platform + "_sbom_version")
    props=bom.get("metadata", {}).get("properties", [])
    check(type(props) is list and
          [p.get("value") for p in props if type(p) is dict and p.get("name")=="flowbridge:source_sha"]==[SOURCE],
          platform + "_sbom_source_pin")
    components=bom.get("components")
    check(type(components) is list and
          len(components)==meta.get("component_count") and
          (platform=="windows" and len(components)==71 or
           platform=="macos" and len(components)==37), platform + "_component_count")
    refs=set()
    missing_licenses=[]
    license_obligations=[]
    for item in components:
        check(type(item) is dict,platform+"_component_shape")
        key=item.get("bom-ref")
        check(type(key) is str and key not in refs and key.startswith("pkg:"),
              platform+"_component_reference")
        refs.add(key)
        licenses=item.get("licenses")
        if type(licenses) is not list or not licenses:
            missing_licenses.append(key)
            continue
        for expression in licenses:
            if type(expression) is dict and isinstance(expression.get("expression"),str):
                e=expression["expression"]
                if any(token in e.upper() for token in ("GPL", "AGPL", "LGPL", "MPL", "EPL", "CDDL")):
                    license_obligations.append({"component":key,"expression":e})
    check(not missing_licenses,platform+"_missing_license_metadata")
    dependencies=bom.get("dependencies")
    check(type(dependencies) is list and bool(dependencies), platform+"_dependency_graph_missing")
    for d in dependencies:
        check(type(d) is dict and d.get("ref") in refs and
              type(d.get("dependsOn")) is list and
              all(x in refs for x in d["dependsOn"]),platform+"_broken_dependency_reference")
    inventory=meta.get("license_inventory")
    check(type(inventory) is list and len(inventory)>0, platform+"_license_file_inventory_missing")
    names=set()
    for entry in inventory:
        check(type(entry) is dict and type(entry.get("component")) is str and
              entry["component"] not in names and type(entry.get("files")) is list and
              bool(entry["files"]), platform+"_license_inventory_structure")
        names.add(entry["component"])
        for f in entry["files"]:
            check(type(f) is dict and type(f.get("name")) is str and
                  type(f.get("sha256")) is str and HEX.fullmatch(f["sha256"]) is not None,
                  platform+"_license_inventory_file_metadata")
    check(b"resolved component notices" in notices and len(notices)>2000,
          platform+"_notice_text_absent")
    return {"bom_components":len(components), "license_inventory_entries":len(inventory),
            "unresolved_license_metadata":len(missing_licenses),
            "license_expressions_requiring_review":license_obligations,
            "native_runtime_review":"OPEN_NOT_ASSERTED",
            "binary_linkage_review":"NOT_PERFORMED",
            "independent_legal_review":"NOT_PERFORMED"}


def audit_kit(data: bytes, source_license: bytes) -> dict:
    check(sha(data)==KIT_SHA256,"frozen_kit_sha256_mismatch")
    try:
        with zipfile.ZipFile(BytesIO(data)) as kit:
            members=safe_members(kit,max_files=32)
            check("candidate-index.json" in members and "SHA256SUMS.txt" in members,
                  "kit_index_missing")
            index_data=kit.read("candidate-index.json")
            index=load_json(index_data,"candidate_index")
            check(index.get("schema")=="flowbridge-explicit-beta-candidate-v1" and
                  index.get("source_sha")==SOURCE and
                  index.get("workflow_run_id")==RUN and
                  index.get("version")==VERSION and
                  index.get("hosted_candidate_valid") is True and
                  index.get("release_accepted") is False and
                  index.get("publisher_release_approved") is False and
                  index.get("native_release_1_0")=="NO_GO",
                  "candidate_index_identity_or_claim")
            gates=index.get("gates",{})
            check(gates.get("A5_independent_license_review")=="OPEN" and
                  gates.get("A3_owner_windows")=="NOT_RUN" and
                  gates.get("A4_owner_mac")=="NOT_RUN" and
                  gates.get("native_G2_packet_ownership")=="NO_GO",
                  "candidate_index_claim_mismatch")
            records=index.get("files")
            check(type(records) is list and len(records)==23,"candidate_file_count")
            expected={"candidate-index.json","SHA256SUMS.txt"}
            examined={}
            for entry in records:
                check(type(entry) is dict and type(entry.get("path")) is str and
                      type(entry.get("sha256")) is str and type(entry.get("bytes")) is int,
                      "candidate_index_file_shape")
                name=entry["path"]
                check(name not in expected and name in members and
                      HEX.fullmatch(entry["sha256"]) is not None,
                      "candidate_index_file_missing_or_duplicate")
                expected.add(name)
                chunk=kit.read(name)
                check(sha(chunk)==entry["sha256"] and len(chunk)==entry["bytes"],
                      "candidate_index_file_digest")
                examined[name]=chunk
            check(set(members)==expected,"candidate_undeclared_file")
            sums=kit.read("SHA256SUMS.txt").decode("ascii").splitlines()
            digest_lines={f"{entry['sha256']}  {entry['path']}" for entry in records}
            digest_lines.add(f"{sha(index_data)}  candidate-index.json")
            check(len(sums)==24 and set(sums)==digest_lines,"kit_sha256sums_mismatch")
            for path,digest in INSTALLERS.items():
                check(path in examined and sha(examined[path])==digest,
                      "published_installer_digest_mismatch")
    except (zipfile.BadZipFile, UnicodeError, KeyError, OSError) as exc:
        raise AuditError("candidate_zip_invalid") from exc

    license_text=source_license.decode("utf-8",errors="replace")
    check("No separate open-source license has been selected" in license_text and
          "FlowBridge" in license_text,"project_license_contract_changed_review_required")
    win=verify_bom("windows",examined)
    mac=verify_bom("macos",examined)
    return {
        "schema":"flowbridge-frozen-a5-independent-audit-v1",
        "candidate_source_sha":SOURCE,"candidate_run_id":RUN,
        "frozen_kit_sha256":KIT_SHA256,
        "kit_declared_payloads_verified":23,
        "exact_signed_installer_claim":False,
        "windows":win,"macos":mac,
        "technical_inventory_and_hashes":"PASS",
        "project_license_selected":False,
        "independent_license_review_passed":False,
        "native_sdk_runtime_distribution_review_passed":False,
        "security_vulnerability_audit_passed":False,
        "a3_a4_owner_native_accepted":False,
        "a5_accepted":False,"release_accepted":False,
        "result":"TECHNICAL_A5_INVENTORY_PASS_LEGAL_AND_NATIVE_REVIEW_OPEN",
    }


def source_license_from_zip(data:bytes)->bytes:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            members=safe_members(archive,max_files=1000)
            path="flowbridge/LICENSE"
            check(path in members,"source_license_missing")
            return archive.read(path)
    except (zipfile.BadZipFile,KeyError,OSError) as exc:
        raise AuditError("source_zip_invalid") from exc


def unique_file(root:Path, pattern:str)->Path:
    matches=[p for p in root.rglob(pattern) if p.is_file() and not p.is_symlink()]
    check(len(matches)==1,"ambiguous_or_missing_original_file")
    return matches[0]


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--original-artifact-dir",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    args=p.parse_args()
    result={"schema":"flowbridge-frozen-a5-independent-audit-v1",
            "result":"BLOCKED","a5_accepted":False,"release_accepted":False,
            "error_code":None}
    rc=1
    try:
        kit=unique_file(args.original_artifact_dir,KIT)
        src=unique_file(args.original_artifact_dir,"flowbridge-source-"+SOURCE+".zip")
        result=audit_kit(kit.read_bytes(),source_license_from_zip(src.read_bytes()))
        rc=0
    except (AuditError,OSError,ValueError,TypeError) as exc:
        result["error_code"]=str(exc) if isinstance(exc,AuditError) else "read_error"
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(result["result"] + (": "+result["error_code"] if rc else ""))
    return rc


if __name__=="__main__":
    raise SystemExit(main())
