#!/usr/bin/env python3
"""Independent, read-only byte/release-gate audit for the Windows Rust CI candidate.

This intentionally does not execute binaries, modify Windows state, install a
signed driver, or infer packet/owner/protected-mode acceptance from test JSON.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile

FILES = frozenset({"flowbridge-agent.exe", "flowbridge.exe", "flowbridge-panel.exe",
                   "README.md", "manifest.json"})
BINARIES = frozenset({"flowbridge-agent.exe", "flowbridge.exe", "flowbridge-panel.exe"})
MAX_MEMBER = 32 * 1024 * 1024
REQUIRED_SOFT = frozenset({
    "no_consent_no_unsafe_port_no_other_app", "unarmed_permit_denied",
    "baseline_selected", "baseline_sibling", "baseline_python",
    "persistent_ipv4_ipv6_ready", "persistent_selected_denied",
    "persistent_other_port_denied", "persistent_sibling_allowed",
    "dynamic_soft_lease_readback", "persistent_deny_still_readable",
    "only_test_port_admitted", "other_port_still_denied",
    "sibling_unchanged", "python_unchanged", "independent_veto_readback",
    "independent_sublayer_vetoes_soft_permit", "independent_veto_not_global",
    "selected_recovers_after_independent_veto_death",
    "held_tcp_live_before_crash", "lease_killed", "lease_filters_removed_automatically",
    "held_tcp_revoked_on_lease_crash", "persistent_after_lease_death",
    "selected_denied_again", "sibling_still_allowed", "guard_killed",
    "persistent_survives_guard_crash", "selected_stays_denied",
    "exact_recovery", "lease_still_absent", "selected_restored", "other_port_restored",
})
FALSE_CANDIDATE = ("legacy_cpp_wfp_helper_included", "vendor_binary_included",
                   "protected_mode_available", "win10_11_accepted", "release_accepted")
FALSE_WFP = ("driver_used", "native_packet_to_pid", "nonleased_port_bypass",
             "hard_permit", "protected_fail_closed", "dns_leak_free",
             "win10_11_accepted", "release_accepted")
FALSE_INSTALLER = ("signed", "native_driver_installed_or_modified",
                   "scm_service_installed_or_modified", "contains_legacy_cpp_wfp",
                   "contains_vendor_binary", "native_packet_pid_proof",
                   "protected_fail_closed", "dns_leak_free", "windows_10_11_accepted",
                   "release_accepted")
FALSE_INSTALLED = ("driver_installed_or_modified", "protected_fail_closed",
                   "native_packet_pid_proof", "dns_leak_free", "win10_11_acceptance",
                   "release_accepted")
TRUE_INSTALLED = ("installed_hashes_match_manifest", "real_windows_ssh_banner_transport",
                  "real_windows_pipe_socks_reload_stop", "installed_real_authenticated_banner_ssh_socks",
                  "installed_gui_real_authenticated_ssh_socks", "installed_native_rust_panel_operated_real_socks",
                  "fault_injected_partial_copy_rolled_back",
                  "fault_injected_written_uninstaller_rolled_back",
                  "successful_real_install_after_two_fault_rollbacks",
                  "reinstall_refused_without_partial_mutation", "registry_removed",
                  "scm_service_unmodified")
SHA_RE = re.compile(r"[a-f0-9]{40}\Z")


def require(predicate: bool, reason: str) -> None:
    if not predicate:
        raise ValueError(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    require(type(obj) is dict, "report must be JSON object")
    return obj


def require_flag(report: dict, names: tuple[str, ...], expected: bool) -> None:
    for key in names:
        require(report.get(key) is expected, f"missing or unsafe acceptance flag: {key}")


def pe_amd64(data: bytes) -> None:
    require(len(data) >= 0x80 and data[:2] == b"MZ", "missing MZ header")
    off = struct.unpack_from("<I", data, 0x3c)[0]
    require(0x40 <= off <= len(data) - 26 and data[off:off + 4] == b"PE\0\0",
            "malformed PE header")
    require(struct.unpack_from("<H", data, off + 4)[0] == 0x8664 and
            struct.unpack_from("<H", data, off + 24)[0] == 0x20b,
            "expected PE32+ AMD64")


def inspect_candidate(path: Path, head: str, merge: str) -> tuple[dict, dict]:
    require(path.is_file() and not path.is_symlink(), "missing/linked candidate ZIP")
    with zipfile.ZipFile(path) as z:
        items = z.infolist()
        require(len(items) == len(FILES) and {x.filename for x in items} == FILES,
                "unexpected, duplicated, missing or path-traversal ZIP entry")
        require(all(not x.is_dir() and 0 < x.file_size <= MAX_MEMBER and
                    (x.external_attr >> 16) & 0o170000 != 0o120000 for x in items),
                "oversized, empty, directory or symlink ZIP entry")
        require(z.testzip() is None, "bad ZIP CRC")
        payload = {x.filename: z.read(x) for x in items}
    manifest = json.loads(payload["manifest.json"])
    require(type(manifest) is dict and manifest.get("kind") == "integration_candidate_NOT_RELEASE"
            and manifest.get("schema") == 1, "invalid candidate manifest")
    require(manifest.get("pr_head_sha") == head and manifest.get("source_commit") == merge,
            "GitHub PR HEAD/merge SHA mismatch")
    require(manifest.get("payload_sha256") ==
            {name: sha(data) for name, data in payload.items() if name != "manifest.json"},
            "manifest not exact or payload SHA mismatch")
    require_flag(manifest, FALSE_CANDIDATE, False)
    for name in BINARIES:
        pe_amd64(payload[name])
    return manifest, {"candidate_sha256": sha(path.read_bytes()),
                      "manifest_sha256": sha(payload["manifest.json"]),
                      "payload_sha256": manifest["payload_sha256"]}


def audit(candidate: Path, wfp: Path, installer_report: Path,
          installed_report: Path, installer_binary: Path,
          head: str, merge: str) -> dict:
    require(bool(SHA_RE.fullmatch(head)) and bool(SHA_RE.fullmatch(merge)),
            "exact 40-digit lower-case SHA required")
    _, info = inspect_candidate(candidate, head, merge)
    w = read_json(wfp)
    require(w.get("kind") == "native_wfp_soft_lease_over_persistent_appwide_deny"
            and w.get("passed") is True, "WFP proof not successful")
    require_flag(w, FALSE_WFP, False)
    checks = w.get("checks")
    require(type(checks) is dict and REQUIRED_SOFT.issubset(checks),
            "missing held TCP/sublayer/revocation/cleanup strict checks")
    require(all(v is True for v in checks.values()), "some WFP proof checks not true")
    b = read_json(installer_report)
    require(b.get("kind") == "unsigned_user_owned_rust_ssh_socks_candidate_installer_NOT_RELEASE"
            and b.get("passed") is True and b.get("qa_fault_fixture") is False and
            b.get("qa_abort_stage") is None, "unsafe installer report kind")
    require(b.get("pr_head_sha") == head and b.get("source_merge_sha") == merge,
            "installer provenance mismatch")
    require_flag(b, FALSE_INSTALLER, False)
    require(b.get("candidate_archive_sha256") == info["candidate_sha256"] and
            b.get("candidate_source_manifest_sha256") == info["manifest_sha256"],
            "installer did not use exact candidate bytes")
    require(b.get("includes_gui") is True and
            b.get("gui_scope") == "same_user_explicit_ssh_socks_only", "GUI scope mismatch")
    require(installer_binary.is_file() and not installer_binary.is_symlink() and
            sha(installer_binary.read_bytes()) == b.get("installer_sha256"),
            "installer binary SHA mismatch")
    inst = read_json(installed_report)
    require(inst.get("kind") == "installed_original_rust_ssh_socks_candidate_windows_server_hosted_only"
            and inst.get("passed") is True, "installed end-to-end not accepted")
    require(inst.get("pr_head_sha") == head and inst.get("source_merge_sha") == merge,
            "installed source/ref mismatch")
    require_flag(inst, FALSE_INSTALLED, False)
    require_flag(inst, TRUE_INSTALLED, True)
    require(inst.get("installer_sha256") == b.get("installer_sha256"),
            "installed executable different from verified installer")
    require(type(b.get("payload_sha256")) is dict and
            all(b["payload_sha256"].get(name) == h for name, h in info["payload_sha256"].items()),
            "installer staged Rust binaries different from candidate")
    return {"kind": "independent_windows_rust_candidate_byte_and_security_gate_audit",
            "passed": True, "pr_head_sha": head, "source_merge_sha": merge,
            "candidate_sha256": info["candidate_sha256"],
            "manifest_sha256": info["manifest_sha256"],
            "agent_sha256": info["payload_sha256"]["flowbridge-agent.exe"],
            "installer_sha256": b["installer_sha256"],
            "wfp_strict_true_checks": len(checks),
            "same_sublayer_revoked_held_tcp_on_lease_death": True,
            "independent_sublayer_veto_verified": True,
            "actual_driver_divert_tested": False, "native_packet_to_pid_proven": False,
            "protected_fail_closed": False, "dns_leak_free": False,
            "windows_10_11_accepted": False, "release_accepted": False}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    for key in ("candidate", "wfp", "installer-report", "installed-report", "installer-binary",
                "head", "merge", "output"):
        ap.add_argument("--" + key, required=True)
    a = ap.parse_args()
    result = audit(Path(a.candidate), Path(a.wfp), Path(a.installer_report),
                   Path(a.installed_report), Path(a.installer_binary), a.head, a.merge)
    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
