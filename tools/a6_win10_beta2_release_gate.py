#!/usr/bin/env python3
"""Independent read-only A6 pre-review of the exact Windows 10 beta.2.

Designed for public original CI artifacts and optional private owner V4+V5 ZIPs.
Never installs a product, loads a driver, grants a license, or approves a release.
"""
from __future__ import annotations
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
import sys
from zipfile import BadZipFile, ZipFile

SOURCE = "86583a1a0487b9d383c0122b24558e620bde5b9c"
TREE = "9f92e9e9e87725d127505c8ac415f37e42a8d148"
RUN = "43883696169"
VERSION = "0.3.0-beta.2"
KIT = "FlowBridge-0.3.0-beta.2-candidate-86583a1a0487.zip"
KIT_SHA = "9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae"
SOURCE_ZIP_SHA = "f37533b57453ecbc79efd014d9dbc405e6076b2c9b35f823ecae1e56684f3628"
WIN_INSTALLER_SHA = "0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4"
GUI_SHA = "0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e"
FFI_SHA = "23b62d54a89feea53331f3ac68fe7c3d348ca99ed72d816f3dcfbc94ef3fd2b4"
V4_SHA = "23844631907f96063f0b13db73a835b92c386a4be3ed13a174c484c3139606e2"
V5_SHA = "809dee21f0884e0d31dfa89a98033276cefaad859de1de64a87a2b90f454cb4c"
ECHO = "0001027F80FEFF410042"
HEX64 = re.compile(r"^[0-9a-f]{64}$")

class GateError(ValueError):
    pass

def need(ok: bool, code: str) -> None:
    if not ok:
        raise GateError(code)

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read_json(data: bytes, code: str) -> dict:
    need(len(data) < 2_000_000, code + "_oversized")
    try:
        value = json.loads(data)
    except (UnicodeError, ValueError) as exc:
        raise GateError(code + "_invalid") from exc
    need(isinstance(value, dict), code + "_not_object")
    return value

def archive(data: bytes, *, directories=False, max_count=400, max_bytes=70_000_000) -> dict[str, bytes]:
    try:
        with ZipFile(BytesIO(data)) as z:
            infos = z.infolist()
            need(0 < len(infos) <= max_count, "zip_file_count")
            need(sum(i.file_size for i in infos) <= max_bytes, "zip_size")
            seen = set()
            items = {}
            for info in infos:
                # On Windows zipfile normalizes backslashes in .filename.
                # .orig_filename retains the untrusted raw ZIP entry name.
                # Reject any normalization, including backslashes and NUL.
                need(info.orig_filename == info.filename, "zip_path")
                name = info.orig_filename[:-1] if info.is_dir() else info.orig_filename
                p = PurePosixPath(name)
                need((not info.is_dir() or directories) and name == p.as_posix()
                     and not name.startswith(("/", "./"))
                     and "\\" not in name and not re.match(r"^[A-Za-z]:", name)
                     and all(x not in ("", ".", "..") for x in name.split("/")), "zip_path")
                need(((info.external_attr >> 16) & 0o170000) != 0o120000, "zip_symlink")
                need(name.casefold() not in seen, "zip_casefold_duplicate")
                seen.add(name.casefold())
                if not info.is_dir():
                    items[name] = z.read(info)
            need(z.testzip() is None, "zip_crc")
            return items
    except (BadZipFile, OSError, RuntimeError, KeyError) as exc:
        raise GateError("zip_invalid") from exc

def manifest(items: dict[str, bytes], count: int) -> None:
    need("sha256-manifest.json" in items, "manifest_missing")
    rows = read_json(items["sha256-manifest.json"], "manifest").get("files")
    need(isinstance(rows, list) and len(rows) == count, "manifest_count")
    seen = set()
    for r in rows:
        need(isinstance(r, dict), "manifest_row")
        name, sha, size = r.get("path"), r.get("sha256"), r.get("bytes")
        need(isinstance(name, str) and name not in seen and isinstance(sha, str)
             and HEX64.fullmatch(sha) and type(size) is int and size >= 0, "manifest_fields")
        need(name in items and digest(items[name]) == sha and len(items[name]) == size,
             "manifest_digest")
        seen.add(name)
    need(set(items) == seen | {"sha256-manifest.json"}, "manifest_extra")

def original_kit(root: Path) -> dict:
    need(root.is_dir(), "original_artifact_missing")
    kit_path = root / KIT
    src_path = root / ("flowbridge-source-" + SOURCE + ".zip")
    need(kit_path.is_file() and src_path.is_file()
         and not kit_path.is_symlink() and not src_path.is_symlink(), "original_archive_missing")
    kit_bytes, source_bytes = kit_path.read_bytes(), src_path.read_bytes()
    need(digest(kit_bytes) == KIT_SHA, "original_kit_sha")
    need(digest(source_bytes) == SOURCE_ZIP_SHA, "original_source_sha")
    src = archive(source_bytes, directories=True, max_count=700)
    need("flowbridge/LICENSE" in src, "source_license_absent")
    need(b"No separate open-source license has been selected" in src["flowbridge/LICENSE"],
         "project_license_claim_mismatch")
    files = archive(kit_bytes, max_count=32)
    index = read_json(files["candidate-index.json"], "candidate")
    need(index.get("source_sha") == SOURCE and index.get("source_tree_sha") == TREE
         and index.get("workflow_run_id") == RUN and index.get("version") == VERSION
         and index.get("schema") == "flowbridge-explicit-beta-candidate-v1", "candidate_source")
    rows = index.get("files")
    need(isinstance(rows, list) and len(rows) == 21, "candidate_payload_count")
    expected = {"candidate-index.json", "SHA256SUMS.txt"}
    for r in rows:
        name = r.get("path")
        need(isinstance(name, str) and name in files and name not in expected
             and r.get("sha256") == digest(files[name]) and r.get("bytes") == len(files[name]),
             "candidate_payload_sha")
        expected.add(name)
    need(set(files) == expected, "candidate_extra_payload")
    checks = {f"{r['sha256']}  {r['path']}" for r in rows}
    checks.add(f"{digest(files['candidate-index.json'])}  candidate-index.json")
    sums = files["SHA256SUMS.txt"].decode("ascii").splitlines()
    need(set(sums) == checks and len(sums) == 22, "candidate_sha256sums")
    setup = "windows/FlowBridge-0.3.0-beta.2-windows-x64-setup.exe"
    need(digest(files[setup]) == WIN_INSTALLER_SHA, "installer_sha")
    wm = read_json(files["windows/explicit-beta-package.json"], "windows_manifest")
    need(wm.get("source_sha") == SOURCE, "windows_manifest_source")
    for name, value in (("FlowBridge.exe", GUI_SHA), ("flowbridge_ffi.dll", FFI_SHA)):
        need(any(r.get("path") == name and r.get("sha256") == value
                 for r in wm.get("payload", [])), "windows_product_binary_sha")
    gates = index.get("gates", {})
    need(index.get("release_accepted") is False
         and index.get("publisher_release_approved") is False
         and index.get("native_release_1_0") == "NO_GO"
         and gates.get("A5_independent_license_review") == "OPEN"
         and gates.get("A6_independent_release_review") == "OPEN"
         and gates.get("A7_publication") == "NOT_RELEASED", "false_release_claim")
    return {"exact_immutable_kit_sha256": KIT_SHA, "source_sha": SOURCE,
            "windows_installer_sha256": WIN_INSTALLER_SHA,
            "windows_gui_sha256": GUI_SHA, "windows_ffi_sha256": FFI_SHA,
            "declared_kit_files": len(files), "status": "PASS_ORIGINAL_BYTES",
            "project_specific_license_selected": False}

def original_owner(data: bytes, *, expected_sha: str, count: int) -> dict[str, bytes]:
    need(digest(data) == expected_sha, "owner_original_outer_sha")
    records = archive(data, max_count=150, max_bytes=50_000_000)
    manifest(records, count)
    return records

def restored(f: dict[str, bytes]) -> None:
    rows = json.loads(f["restore-checks.json"])
    need(isinstance(rows, list) and len(rows) >= 4, "restore_count")
    need(all(all(r.get(k) is True for k in ("hash_match", "acl_match", "time_match",
                                           "attributes_match", "count_match")) for r in rows),
         "restore_file_evidence")
    c = read_json(f["cleanup.json"], "cleanup")
    need(c.get("registry_equal") is True and c.get("escrow_restored") is True
         and c.get("processes") == [] and c.get("test_install_exists") is False
         and c.get("uninstall_key_exists") is False, "cleanup_failure")

def positive_echo(f: dict, code: str) -> None:
    need(f.get("ok") is True and f.get("atyp") == "DOMAINNAME"
         and f.get("domain") == "localhost" and f.get("hello") == "0500"
         and f.get("reply") == "05000001" and f.get("payload_hex") == ECHO
         and f.get("up_hex") == ECHO and f.get("down_hex") == ECHO
         and f.get("client_eof") is True and f.get("target_eof") is True
         and f.get("direct_pending") is False, code)

def owner_v4_v5(v4: bytes, v5: bytes) -> dict:
    p = original_owner(v4, expected_sha=V4_SHA, count=100)
    q = original_owner(v5, expected_sha=V5_SHA, count=26)
    candidate = read_json(p["report.json"], "owner_v4_report")["candidate"]
    need(candidate.get("source_sha") == SOURCE and candidate.get("version") == VERSION
         and candidate.get("gui_sha256") == GUI_SHA and candidate.get("ffi_sha256") == FFI_SHA
         and candidate.get("installer_sha256") == WIN_INSTALLER_SHA, "owner_v4_binary_pins")
    native = read_json(p["lifecycle/native-acceptance.json"], "owner_v4_native")
    need(native.get("source_sha") == SOURCE
         and native.get("status") == "OWNER_NATIVE_AUTOMATED_CHECKS_PASS"
         and set(native.get("checks", {}).values()) == {"PASS"}
         and set(native.get("checks", {})) ==
         {"install", "launch", "payload", "upgrade", "uninstall", "stable_preserved"},
         "owner_win10_lifecycle")
    positive_echo(read_json(p["ssh/gui-echo.json"], "owner_v4_echo"), "v4_ssh_echo")
    gone = read_json(p["ssh/all-down-timed.json"], "owner_v4_all_down")
    need(gone.get("elapsed_ms", 0) >= 30000
         and gone.get("target_accepted") is False
         and gone.get("reply", "").startswith("0501"), "v4_all_down")
    pf = read_json(q["preflight.json"], "owner_v5_preflight")
    need(pf.get("source_sha") == SOURCE and pf.get("source_tree") == TREE
         and pf.get("exe_sha256", "").lower() == GUI_SHA
         and pf.get("dll_sha256", "").lower() == FFI_SHA
         and pf.get("installer_sha256", "").lower() == WIN_INSTALLER_SHA
         and pf.get("v4_original_zip_sha256") == V4_SHA, "owner_v5_binary_pins")
    verdict = read_json(q["verdict.json"], "owner_v5_verdict")
    need(verdict.get("verdict") == "PASS_FINAL_BETA2_INVALID_KEY_PATH"
         and verdict.get("identity_path_exists_before") is False
         and verdict.get("negative_pass") is True and verdict.get("positive_pass") is True
         and verdict.get("cleanup_pass") is True
         and verdict.get("negative_socks_rep") is None
         and verdict.get("release_accepted") is False, "owner_v5_verdict")
    neg = read_json(q["ssh/negative.json"], "owner_v5_negative")
    need(len(neg.get("attempts", [])) == 12
         and all(x.get("connect") is False and x.get("rep") is None
                 for x in neg["attempts"])
         and neg.get("target_accept_count") == 0 and neg.get("gui_listeners") == [],
         "owner_v5_denial_no_listener")
    positive_echo(read_json(q["ssh/positive.json"], "owner_v5_positive"), "v5_ssh_echo")
    stop = read_json(q["ssh/stop.json"], "owner_v5_stop")
    need(stop.get("ssh_children") == [] and stop.get("gui_listeners") == [], "owner_v5_stop")
    need(len(q["actions.jsonl"].decode("utf8").splitlines()) == 23,
         "owner_v5_gui_actions")
    need(len([x for x in p if x.startswith("screenshots/") and x.endswith(".png")]) == 17
         and len([x for x in q if x.startswith("screenshots/") and x.endswith(".png")]) == 6,
         "owner_gui_png")
    restored(p)
    restored(q)
    return {"status": "PASS_SUBMITTED_ORIGINAL_OWNER_EVIDENCE",
            "v4_manifest_files": "100/100", "v5_manifest_files": "26/26",
            "v4_gui_png": 17, "v5_gui_png": 6, "v5_gui_actions": 23,
            "wrong_key_denial": "12 TCP opens rejected; no SOCKS listener; REP=null",
            "healthy_control": "SOCKS5h 10-byte binary echo, EOF, Stop",
            "physical_reviewer_rerun": False, "host_cryptographically_attested": False}

def review(candidate_dir: Path, v4: bytes | None = None,
           v5: bytes | None = None) -> dict:
    result = {
        "schema": "flowbridge-a6-win10-beta2-technical-review-v1",
        "scope": "Windows 10 Pro 22H2 x64 ONLY; Win11/macOS deferred, not PASSED",
        "candidate": original_kit(candidate_dir),
        "owner_original_evidence": None,
        "a0_a3_win10_technical_evidence_ready": False,
        "a5_legal_and_native_review_accepted": False,
        "a6_release_approved": False, "a7_publication_approved": False,
        "publisher_release_approved": False, "release_accepted": False,
        "wfp_g2_accepted": False,
        "remaining": ["A5 owner license choice + independent native SDK/legal/C++ review",
                      "A6 independent final Windows 10 privacy and P0 release signoff",
                      "A7 explicit publisher GO; no tag or GitHub Release"]
    }
    if v4 is not None or v5 is not None:
        need(v4 is not None and v5 is not None, "owner_evidence_incomplete")
        result["owner_original_evidence"] = owner_v4_v5(v4, v5)
        result["a0_a3_win10_technical_evidence_ready"] = True
    result["status"] = ("A6_TECHNICAL_EVIDENCE_PASS_RELEASE_GO_BLOCKED"
                        if result["a0_a3_win10_technical_evidence_ready"]
                        else "ORIGINAL_CANDIDATE_PASS_PRIVATE_A3_REVIEW_NOT_RUN")
    return result

def main() -> int:
    a = argparse.ArgumentParser()
    a.add_argument("--original-candidate-directory", required=True, type=Path)
    a.add_argument("--v4-owner-zip", type=Path)
    a.add_argument("--v5-owner-zip", type=Path)
    a.add_argument("--output", required=True, type=Path)
    args = a.parse_args()
    result = {"status": "BLOCKED", "release_accepted": False, "error_code": None}
    rc = 1
    try:
        result = review(args.original_candidate_directory,
                        args.v4_owner_zip.read_bytes() if args.v4_owner_zip else None,
                        args.v5_owner_zip.read_bytes() if args.v5_owner_zip else None)
        rc = 0
    except (GateError, KeyError, TypeError, ValueError, OSError) as exc:
        result["error_code"] = str(exc) if isinstance(exc, GateError) else "original_evidence_invalid"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf8")
    print(result["status"] + ((": " + str(result["error_code"])) if rc else ""))
    return rc

if __name__ == "__main__":
    sys.exit(main())
