#!/usr/bin/env python3
"""Independent, non-mutating verifier for the frozen 0.3.0-beta.1 macOS A4 kit.

The actual pkg install/launch/upgrade/uninstall is performed ONLY by the
original source-pinned operator tool inside the frozen kit in GitHub CI.
These verdicts cannot authorize publication, NE, owner native A4, or G2.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

SOURCE = "f5ecd48d8f81c594f755a55e7969b57d20903020"
RUN_ID = "43407093536"
VERSION = "0.3.0-beta.1"
KIT_SHA = "4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8"
PKG_SHA = "7eb645e227442ba5a2d12bc1b9c5853212baf8a3d28e7215640f0e3e2ec0453c"
MANIFEST_SHA = "ed00c3257a4b5f1db453169fc802c3ba85215265bb2dce783d79275cbb386a03"
TOOL_SHA = "faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c"
MAC_PKG = "macos/FlowBridge-0.3.0-beta.1-macOS-universal-explicit-beta.pkg"
ARCHES = ("arm64", "x86_64")
PHASES = ("install", "payload", "launch", "upgrade", "uninstall", "stable_preserved")
SCHEMA = "flowbridge-frozen-beta-macos-dualarch-v1"


class Fail(Exception):
    pass


def must(condition: bool, code: str) -> None:
    if not condition:
        raise Fail(code)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for blob in iter(lambda: f.read(1024 * 1024), b""):
            h.update(blob)
    return h.hexdigest()


def read(path: Path) -> dict:
    must(path.is_file() and not path.is_symlink(), "json_absent_or_link")
    must(path.stat().st_size < 1500000, "json_oversized")
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise Fail("json_malformed") from exc
    must(type(content) is dict, "json_not_object")
    return content


def file(root: Path, relative: str, expected: str, size: int | None = None) -> None:
    must(re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", relative) is not None
         and all(x not in (".", "..", "") for x in relative.split("/")),
         "unsafe_relative_path")
    path = root / relative
    must(path.is_file() and not path.is_symlink(), "payload_missing_or_link")
    must(path.resolve(strict=True).is_relative_to(root.resolve(strict=True)),
         "payload_outside_kit")
    must(re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
         "invalid_expected_sha")
    if size is not None:
        must(type(size) is int and size >= 0 and path.stat().st_size == size,
             "payload_size_mismatch")
    must(sha(path) == expected, "payload_sha_mismatch")


def verify_kit(root: Path, arch: str) -> dict:
    must(arch in ARCHES, "unsupported_arch")
    index = read(root / "candidate-index.json")
    must(index.get("schema") == "flowbridge-explicit-beta-candidate-v1"
         and index.get("source_sha") == SOURCE
         and str(index.get("workflow_run_id")) == RUN_ID
         and index.get("version") == VERSION
         and index.get("hosted_candidate_valid") is True
         and index.get("release_accepted") is False
         and index.get("publisher_release_approved") is False,
         "candidate_source_or_scope_mismatch")
    gates = index.get("gates", {})
    must(type(gates) is dict
         and gates.get("A4_owner_mac") == "NOT_RUN"
         and gates.get("A5_independent_license_review") == "OPEN"
         and gates.get("native_G2_packet_ownership") == "NO_GO",
         "candidate_native_go_claim")
    entries = index.get("files")
    must(type(entries) is list and len(entries) == 21, "indexed_file_count")
    paths: set[str] = set()
    for entry in entries:
        must(type(entry) is dict
             and type(entry.get("path")) is str
             and type(entry.get("sha256")) is str
             and type(entry.get("bytes")) is int,
             "invalid_index_entry")
        path = entry["path"]
        must(path.casefold() not in paths, "duplicate_index_path")
        paths.add(path.casefold())
        file(root, path, entry["sha256"], entry["bytes"])
    must(MAC_PKG.casefold() in paths, "mac_pkg_not_indexed")
    file(root, MAC_PKG, PKG_SHA)
    file(root, "macos/explicit-macos-package.json", MANIFEST_SHA)
    file(root, "tools/explicit_beta_acceptance.py", TOOL_SHA)
    manifest = read(root / "macos/explicit-macos-package.json")
    must(manifest.get("schema") == "flowbridge-explicit-beta-macos-qa-package-v1"
         and manifest.get("source_sha") == SOURCE
         and manifest.get("pkg_sha256") == PKG_SHA
         and manifest.get("bundle_id") == "org.flowbridge.FlowBridgeExplicitBeta"
         and manifest.get("system_extension_included") is False,
         "mac_manifest_identity_mismatch")
    sums = (root / "SHA256SUMS.txt").read_text(encoding="ascii").splitlines()
    must(len(sums) == 22, "checksums_count_mismatch")
    expected = set(f"{entry['sha256']}  {entry['path']}" for entry in entries)
    expected.add(f"{sha(root / 'candidate-index.json')}  candidate-index.json")
    must(set(sums) == expected and len(set(sums)) == len(sums),
         "checksums_content_mismatch")
    return {
        "schema": SCHEMA, "status": "FROZEN_KIT_VERIFIED_NATIVE_NOT_RUN",
        "arch": arch, "source_sha": SOURCE, "source_run_id": RUN_ID,
        "kit_sha256": KIT_SHA, "mac_pkg_sha256": PKG_SHA,
        "mac_manifest_sha256": MANIFEST_SHA, "tool_sha256": TOOL_SHA,
        "verified_index_files": len(entries), "verified_sha256sums": len(sums),
        "owner_native_accepted": False, "native_ne_activated": False,
        "physical_dns_no_leak_proved": False, "release_accepted": False,
    }


def verify_native(root: Path, arch: str) -> dict:
    must(arch in ARCHES, "unsupported_arch")
    pre = read(root / f"bytes-{arch}.json")
    native = read(root / f"native-{arch}.json")
    for entry in (pre, native):
        must(entry.get("schema") == "flowbridge-explicit-beta-native-acceptance-v1"
             and entry.get("source_sha") == SOURCE
             and entry.get("target") == "macos"
             and entry.get("package_sha256") == PKG_SHA
             and entry.get("manifest_sha256") == MANIFEST_SHA
             and entry.get("tool_sha256") == TOOL_SHA
             and entry.get("pins_verified") is True
             and entry.get("release_accepted") is False
             and entry.get("a3_a4_full_acceptance") is False,
             "qa_source_or_approval_mismatch")
    must(pre.get("status") == "VERIFIED_BYTES_NATIVE_NOT_RUN"
         and all(pre.get("checks", {}).get(x) == "NOT_RUN" for x in PHASES),
         "preflight_not_read_only")
    must(native.get("status") == "CI_AUTOMATED_CHECKS_PASS"
         and all(native.get("checks", {}).get(x) == "PASS" for x in PHASES),
         "hosted_lifecycle_not_all_pass")
    host = native.get("host")
    must(type(host) is dict
         and host.get("platform") == "macos"
         and host.get("architecture") == arch
         and host.get("github_hosted") is True
         and host.get("ci_environment_detected") is True
         and host.get("owner_native") is False,
         "host_native_arch_or_identity_mismatch")
    must(native.get("macos_launch_scope") ==
         "process survived 4 seconds; visual/routing checks not performed",
         "mac_launch_scope_changed")
    must(native.get("driver_or_extension_activation_requested") is False
         and native.get("network_configuration_requested") is False
         and native.get("publisher_signature_acceptance") == "NOT_RUN"
         and native.get("native_transparent_routing") == "NOT_RUN"
         and native.get("dns_leak_acceptance") == "NOT_RUN"
         and native.get("manual_visual_keyboard_review") == "NOT_RUN"
         and native.get("owner_managed_ssh") == "NOT_RUN"
         and native.get("cleanup_required") is False
         and native.get("test_profile_retained") is True,
         "unsupported_native_or_cleanup_claim")
    return {
        "schema": SCHEMA, "status": "HOSTED_NATIVE_6_6_OWNER_OPEN",
        "arch": arch, "os_version": host.get("os_version"),
        "source_sha": SOURCE, "source_run_id": RUN_ID,
        "mac_pkg_sha256": PKG_SHA, "mac_manifest_sha256": MANIFEST_SHA,
        "operator_tool_sha256": TOOL_SHA, "phases_pass": len(PHASES),
        "real_pkg_install_launch_upgrade_uninstall": True,
        "launch_scope": native["macos_launch_scope"],
        "owner_native_accepted": False, "native_ne_activated": False,
        "physical_dns_no_leak_proved": False, "release_accepted": False,
    }


def compare(root: Path) -> dict:
    data: dict[str, dict] = {}
    for arch in ARCHES:
        found = sorted(root.rglob(f"check-{arch}.json"))
        must(len(found) == 1, "missing_or_duplicate_arch_report")
        d = read(found[0])
        must(d.get("schema") == SCHEMA and d.get("arch") == arch
             and d.get("status") == "HOSTED_NATIVE_6_6_OWNER_OPEN"
             and d.get("phases_pass") == 6
             and d.get("source_sha") == SOURCE
             and d.get("source_run_id") == RUN_ID
             and d.get("mac_pkg_sha256") == PKG_SHA
             and d.get("mac_manifest_sha256") == MANIFEST_SHA
             and d.get("operator_tool_sha256") == TOOL_SHA
             and d.get("owner_native_accepted") is False
             and d.get("native_ne_activated") is False
             and d.get("physical_dns_no_leak_proved") is False
             and d.get("release_accepted") is False,
             "arch_evidence_disagreement_or_false_go")
        data[arch] = d
    return {
        "schema": SCHEMA, "status": "HOSTED_MAC_INTEL_AND_ARM_6_6_OWNER_OPEN",
        "architectures": list(ARCHES),
        "original_frozen_binary_source": SOURCE, "original_run_id": RUN_ID,
        "mac_pkg_sha256": PKG_SHA,
        "architectures_with_real_pkg_lifecycle": len(data),
        "total_hosted_phases_passed": sum(d["phases_pass"] for d in data.values()),
        "owner_native_accepted": False, "native_ne_activated": False,
        "physical_dns_no_leak_proved": False, "release_accepted": False,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="action", required=True)
    for name in ("verify-kit", "verify-native", "compare"):
        child = sub.add_parser(name)
        child.add_argument("--root", type=Path, required=True)
        child.add_argument("--output", type=Path, required=True)
        if name != "compare":
            child.add_argument("--platform", choices=ARCHES, required=True)
    args = ap.parse_args(argv)
    try:
        result = (verify_kit(args.root, args.platform) if args.action == "verify-kit"
                  else verify_native(args.root, args.platform) if args.action == "verify-native"
                  else compare(args.root))
        code = 0
    except (Fail, OSError, UnicodeError, ValueError) as exc:
        result = {"schema": SCHEMA, "status": "BLOCKED",
                  "error_code": str(exc) if isinstance(exc, Fail) else "read_error",
                  "owner_native_accepted": False,
                  "native_ne_activated": False,
                  "physical_dns_no_leak_proved": False, "release_accepted": False}
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(result["status"] + (":" + result["error_code"] if code else ""))
    return code


if __name__ == "__main__":
    sys.exit(main())
