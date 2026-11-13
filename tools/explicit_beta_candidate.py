#!/usr/bin/env python3
"""Assemble one source-pinned, hosted-tested explicit SOCKS beta candidate.

This is a transportable QA bundle, not a publisher or native release approval.
All inputs must come from the same workflow invocation and exact checkout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
WINDOWS_PAYLOAD = {
    "FlowBridge.exe", "flowbridge-cli.exe", "flowbridge_ffi.dll", "LICENSE", "README.txt",
    "SBOM.cdx.json", "BUILD-METADATA.json", "licenses/THIRD_PARTY_NOTICES.txt",
    "licenses/nlohmann-json-LICENSE.MIT", "resources/presets.json",
    "examples/direct.json", "examples/ssh-socks.json", "examples/chain.json",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    require(isinstance(value, dict), f"Expected JSON object: {path.name}")
    return value


def unique(directory: Path, name: str) -> Path:
    matches = [p for p in directory.rglob(name) if p.is_file() and not p.is_symlink()]
    require(len(matches) == 1, f"Expected one {name}, found {len(matches)}")
    return matches[0]


def checked_file(path: Path, sha256: str, size: int | None = None) -> None:
    require(isinstance(sha256, str) and bool(HEX64.fullmatch(sha256)),
            f"Invalid SHA256: {path.name}")
    require(path.is_file() and not path.is_symlink(), f"Regular file required: {path.name}")
    require(not any(parent.is_symlink() for parent in path.parents),
            f"Symlink ancestor rejected: {path.name}")
    require(digest(path) == sha256, f"SHA256 mismatch: {path.name}")
    if size is not None:
        require(type(size) is int and size > 0 and path.stat().st_size == size,
                f"Size mismatch: {path.name}")


def payload_map(manifest: dict) -> dict[str, dict]:
    payload = manifest.get("payload")
    require(isinstance(payload, list) and bool(payload), "Windows payload missing")
    result = {}
    for entry in payload:
        require(isinstance(entry, dict), "Invalid payload record")
        name = entry.get("path")
        require(isinstance(name, str) and "\\" not in name and ":" not in name and
                not PurePosixPath(name).is_absolute() and
                all(part not in ("", ".", "..") for part in name.split("/")),
                "Unsafe payload path")
        require(name.casefold() not in {p.casefold() for p in result}, "Duplicate payload path")
        require(not any(part in name.casefold() for part in
                        ("capture", "wfp", "ndisrd", ".sys", ".inf")),
                "Native helper or driver in explicit payload")
        require(isinstance(entry.get("sha256"), str) and
                bool(HEX64.fullmatch(entry["sha256"])), "Invalid payload hash")
        require(type(entry.get("bytes")) is int and entry["bytes"] > 0, "Invalid payload size")
        result[name] = entry
    require(set(result) == WINDOWS_PAYLOAD, "Explicit Windows payload does not match exact allowlist")
    return result


def validate_reports(source: str, windows: dict, installed: dict, mac: dict,
                     mac_scope: dict, ssh: dict, core: list[dict]) -> dict:
    require(bool(HEX40.fullmatch(source)), "Full source SHA required")
    for label, report in (("Windows", windows), ("Windows install", installed),
                          ("macOS", mac), ("macOS scope", mac_scope)):
        require(report.get("source_sha") == source, f"{label} source SHA mismatch")
    all_reports = [windows, installed, mac, mac_scope, ssh, *core]
    runs = {r.get("workflow_run_id") for r in all_reports}
    require(len(runs) == 1 and isinstance(next(iter(runs)), str) and
            next(iter(runs)).isdecimal(), "Evidence comes from different or unknown workflow runs")
    require(windows.get("schema") == "flowbridge-explicit-beta-windows-qa-package-v1",
            "Wrong Windows manifest schema")
    require(mac.get("schema") == "flowbridge-explicit-beta-macos-qa-package-v1",
            "Wrong macOS manifest schema")
    require(windows.get("candidate") == mac.get("candidate") and
            isinstance(windows.get("candidate"), str) and
            re.fullmatch(r"\d+\.\d+\.\d+-beta\.[1-9]\d*", windows["candidate"]) is not None,
            "Package versions differ or are not beta")
    for label, report in (("Windows", windows), ("macOS", mac)):
        require(report.get("explicit_socks_only") is True and
                report.get("signed") is False and report.get("driver_included") is False and
                report.get("publisher_release_approved") is False,
                f"{label} distribution scope mismatch")
    require(windows.get("capture_helper_included") is False and
            windows.get("system_service_included") is False and
            windows.get("gui_protected_ui_compiled_disabled") is True and
            windows.get("app_specific_interception") is False and
            windows.get("wfp_native_gate") == "NO_GO", "Windows protected scope not excluded")
    require(mac.get("system_extension_included") is False and
            mac.get("bundle_id") == "org.flowbridge.FlowBridgeExplicitBeta",
            "macOS extension or identity scope mismatch")
    require(installed.get("passed") is True and installed.get("on_owner_win10") is False and
            installed.get("installer_sha256") == windows.get("installer_sha256"),
            "Installed Windows bytes were not accepted on hosted runner")
    require(mac_scope.get("source_gate") is True and mac_scope.get("native_package_gate") is True and
            mac_scope.get("extension_present") is False and mac_scope.get("release_accepted") is False and
            mac_scope.get("pkg_sha256") == mac.get("pkg_sha256") and
            set(mac_scope.get("binary_arches", [])) == {"arm64", "x86_64"},
            "Universal explicit macOS package checks incomplete")
    payload = payload_map(windows)
    require(windows.get("sbom_sha256") == payload["SBOM.cdx.json"]["sha256"] and
            windows.get("build_metadata_sha256") == payload["BUILD-METADATA.json"]["sha256"],
            "Windows manifest and embedded inventory hashes disagree")
    require(installed.get("installed_gui_sha256") == payload["FlowBridge.exe"]["sha256"],
            "Installed GUI hash differs from candidate")
    require(ssh.get("source_commit") == source and ssh.get("passed") is True and
            ssh.get("managed_acceptance_proved") is True and ssh.get("scenario") == "managed",
            "Real managed SSH acceptance missing or stale")
    require(ssh.get("ffi_sha256") == payload["flowbridge_ffi.dll"]["sha256"],
            "SSH tested different FFI bytes from Windows installer")
    cli_sha = payload["flowbridge-cli.exe"]["sha256"]
    require(ssh.get("cli_sha256") == cli_sha and
            ssh.get("banner_first_real_ssh", {}).get("cli_sha256") == cli_sha and
            ssh.get("supervised_banner_first_real_ssh", {}).get("cli_sha256") == cli_sha and
            ssh.get("rust_owned_ssh_control", {}).get("banner_helper_sha256") == cli_sha,
            "SSH tested different CLI bytes from Windows installer")
    require(ssh.get("hosted_windows_runner") is True and
            ssh.get("windows_10_11_user_machine_tested") is False and
            ssh.get("wfp_driver_loaded") is False and ssh.get("native_dns_leaks_verified") is False,
            "Hosted SSH report claims unproved native acceptance")
    capacity = ssh.get("managed_capacity", {})
    pool = ssh.get("owned_pool", {})
    require(capacity.get("passed") is True and capacity.get("held") == 128 and
            capacity.get("churn") == 10000 and capacity.get("rejected") == 1152 and
            pool.get("passed") is True and pool.get("independent_children") == 4,
            "Managed 128-channel / 10k churn / four-worker coverage incomplete")
    require(len(core) == 3 and {r.get("runner_os") for r in core} == {"Linux", "Windows", "macOS"},
            "Missing or duplicate core platform report")
    for report in core:
        require(report.get("source_sha") == source and report.get("passed") is True and
                report.get("format") is True and report.get("clippy") is True and
                report.get("workspace_tests") is True and report.get("dns_loopback") is True,
                "Core exact-source checks incomplete")
    trees = {r.get("source_tree_sha") for r in all_reports}
    require(len(trees) == 1 and isinstance(next(iter(trees)), str) and
            bool(HEX40.fullmatch(next(iter(trees)))), "Core source trees differ")
    return {
        "schema": "flowbridge-explicit-beta-candidate-v1", "source_sha": source,
        "workflow_run_id": next(iter(runs)),
        "source_tree_sha": next(iter(trees)), "version": windows["candidate"],
        "hosted_candidate_valid": True, "release_accepted": False,
        "publisher_release_approved": False, "native_release_1_0": "NO_GO",
        "gates": {"A0_scope_and_windows_hosted": "PASS", "A1_same_source_hosted": "PASS",
                  "A2_packaged_ffi_managed_ssh_hosted": "PASS",
                  "A3_owner_windows": "NOT_RUN", "A4_mac_universal_package_hosted": "PASS",
                  "A4_owner_mac": "NOT_RUN", "A5_metadata_and_dependency_inventory": "VALIDATED",
                  "A5_independent_license_review": "OPEN", "A6_independent_release_review": "OPEN",
                  "A7_publication": "NOT_RELEASED", "native_G2_packet_ownership": "NO_GO"},
        "managed_ssh": {"held": 128, "churn": 10000, "independent_children": 4,
                        "ffi_sha256": ssh["ffi_sha256"]},
        "limitations": ["Explicit client proxy configuration required",
                        "Unsigned engineering installers; macOS app uses ad-hoc code signature",
                        "No WFP/NDISRD/Network Extension activation",
                        "No transparent routing, system kill switch or universal DNS no-leak claim",
                        "Native Windows 10/11 and owner macOS acceptance remain open"],
    }


def validate_inventory(directory: Path, source: str, version: str, platform: str) -> dict:
    metadata = load(directory / "BUILD-METADATA.json")
    bom = load(directory / "SBOM.cdx.json")
    notices = directory / ("licenses/THIRD_PARTY_NOTICES.txt" if platform == "windows"
                           else "THIRD_PARTY_NOTICES.txt")
    require(metadata.get("schema") == "flowbridge-explicit-beta-build-metadata-v1" and
            metadata.get("source_sha") == source and metadata.get("version") == version and
            metadata.get("platform") == platform and metadata.get("explicit_socks_only") is True,
            "Embedded build metadata identity mismatch")
    require(metadata.get("publisher_release_approved") is False and
            metadata.get("binary_linkage_reviewed") is False and
            metadata.get("independent_license_review_passed") is False and
            metadata.get("vulnerability_audit_performed") is False,
            "Dependency inventory claims unperformed review")
    checked_file(directory / "SBOM.cdx.json", metadata.get("sbom_sha256"))
    checked_file(notices, metadata.get("notices_sha256"))
    checked_file(ROOT / "Cargo.lock", metadata.get("cargo_lock_sha256"))
    checked_file(ROOT / "packaging/explicit-beta.json", metadata.get("version_contract_sha256"))
    contract = load(ROOT / "packaging/explicit-beta.json")
    require(contract.get("schema") == "flowbridge-explicit-beta-version-v1" and
            contract.get("version") == version and contract.get("release_approved") is False,
            "Candidate version differs from frozen version contract")
    require(bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion") == "1.5" and
            bom.get("version") == 1 and isinstance(bom.get("components"), list) and
            bool(bom["components"]) and metadata.get("component_count") == len(bom["components"]),
            "Dependency inventory is not the expected nonempty CycloneDX document")
    require(bom.get("metadata", {}).get("component", {}).get("version") == version,
            "SBOM product version mismatch")
    properties = bom.get("metadata", {}).get("properties", [])
    require([p.get("value") for p in properties if p.get("name") == "flowbridge:source_sha"] == [source],
            "SBOM source mismatch or duplicate provenance")
    return metadata


def validate_qa_runner(report: dict, *, source: str, run_id: str, platform: str,
                       package: Path, manifest: Path, tool: Path) -> None:
    require(report.get("schema") == "flowbridge-explicit-beta-native-acceptance-v1" and
            report.get("status") == "CI_AUTOMATED_CHECKS_PASS" and
            report.get("source_sha") == source and report.get("workflow_run_id") == run_id and
            report.get("target") == platform, "QA runner was not exercised on this candidate")
    require(report.get("package_sha256") == digest(package) and
            report.get("manifest_sha256") == digest(manifest) and
            report.get("tool_sha256") == digest(tool), "QA runner pins differ from delivered kit")
    host = report.get("host", {})
    require(host.get("github_hosted") is True and host.get("ci_environment_detected") is True and
            host.get("owner_native") is False and report.get("release_accepted") is False and
            report.get("a3_a4_full_acceptance") is False, "Hosted QA runner claims owner approval")
    checks = report.get("checks", {})
    require(all(checks.get(k) == "PASS" for k in
                ("install", "payload", "launch", "upgrade", "uninstall", "stable_preserved")),
            "QA runner did not complete all lifecycle checks")


def assemble(inputs: Path, output: Path, source: str, run_id: str) -> Path:
    require(not output.exists(), "Candidate output must be a new directory")
    require(run_id.isdecimal(), "Numeric GitHub workflow run ID required")
    manifest_names = ["explicit-beta-package.json", "explicit-beta-installer-result.json",
                      "explicit-macos-package.json", "native-package.json", "summary.json"]
    reports = {name: unique(inputs, name) for name in manifest_names}
    w, installed, mac, scope, ssh = [load(reports[name]) for name in manifest_names]
    core_paths = [unique(inputs, f"core-{os_name}.json") for os_name in ("Linux", "Windows", "macOS")]
    verdict = validate_reports(source, w, installed, mac, scope, ssh, [load(p) for p in core_paths])
    require(verdict["workflow_run_id"] == run_id, "Inputs do not belong to this workflow run")
    local_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    local_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
    require(local_sha == source and local_tree == verdict["source_tree_sha"],
            "Assembler checkout differs from tested source")
    require(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT),
            "Assembler tracked source is dirty")
    version = verdict["version"]
    win_exe = unique(inputs, f"FlowBridge-{version}-windows-x64-setup.exe")
    mac_pkg = unique(inputs, f"FlowBridge-{version}-macOS-universal-explicit-beta.pkg")
    harness = unique(inputs, "FlowBridgeNativeSmoke.exe")
    checked_file(win_exe, w["installer_sha256"], w["installer_bytes"])
    checked_file(mac_pkg, mac["pkg_sha256"], mac["pkg_bytes"])
    checked_file(harness, w["qa_harness"]["sha256"], w["qa_harness"]["bytes"])
    # Check staged payload bytes, including source-pinned metadata and SBOM.
    payload = payload_map(w)
    stage = unique(inputs, "flowbridge_ffi.dll").parent
    for name, item in payload.items():
        checked_file(stage / name, item["sha256"], item["bytes"])
    validate_inventory(stage, source, version, "windows")
    mac_metadata = [p for p in inputs.rglob("BUILD-METADATA.json")
                    if p.is_file() and load(p).get("platform") == "macos"]
    require(len(mac_metadata) == 1, "macOS build metadata missing or ambiguous")
    checked_file(mac_metadata[0], mac["build_metadata_sha256"])
    checked_file(mac_metadata[0].parent / "SBOM.cdx.json", mac.get("sbom_sha256"))
    validate_inventory(mac_metadata[0].parent, source, version, "macos")
    qa_reports = []
    for os_name, platform, package, manifest in (
        ("Windows", "windows", win_exe, reports["explicit-beta-package.json"]),
        ("macOS", "macos", mac_pkg, reports["explicit-macos-package.json"]),
    ):
        path = unique(inputs, f"native-qa-{os_name}.json")
        validate_qa_runner(load(path), source=source, run_id=run_id, platform=platform,
                           package=package, manifest=manifest, tool=ROOT / "tools/explicit_beta_acceptance.py")
        qa_reports.append(path)
    verdict["gates"]["operator_qa_runner_hosted_windows_and_macOS"] = "PASS"
    output.mkdir(parents=True)
    entries = []

    def add(original: Path, relative: str) -> None:
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        entries.append({"path": relative, "sha256": digest(target), "bytes": target.stat().st_size})

    add(win_exe, "windows/" + win_exe.name)
    add(mac_pkg, "macos/" + mac_pkg.name)
    add(reports["explicit-beta-package.json"], "windows/explicit-beta-package.json")
    add(reports["explicit-macos-package.json"], "macos/explicit-macos-package.json")
    add(harness, "windows/FlowBridgeNativeSmoke.exe")
    add(ROOT / "tools/explicit_beta_acceptance.py", "tools/explicit_beta_acceptance.py")
    add(ROOT / "docs/qa/EXPLICIT_BETA_NATIVE_ACCEPTANCE.md", "NATIVE-ACCEPTANCE.md")
    for name in ("explicit-beta-installer-result.json", "native-package.json", "summary.json"):
        add(reports[name], "evidence/" + name)
    for path in core_paths:
        add(path, "evidence/" + path.name)
    for path in qa_reports:
        add(path, "evidence/" + path.name)
    for name in ("SBOM.cdx.json", "BUILD-METADATA.json"):
        add(stage / name, "windows/" + name)
    add(stage / "licenses/THIRD_PARTY_NOTICES.txt", "windows/THIRD_PARTY_NOTICES.txt")
    for name in ("SBOM.cdx.json", "BUILD-METADATA.json", "THIRD_PARTY_NOTICES.txt"):
        add(mac_metadata[0].parent / name, "macos/" + name)
    verdict["workflow_run_id"] = run_id
    verdict["workflow_url"] = f"https://github.com/i-shutov/flowbridge/actions/runs/{run_id}"
    verdict["files"] = sorted(entries, key=lambda item: item["path"])
    index = output / "candidate-index.json"
    index.write_text(json.dumps(verdict, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    sums = [f"{item['sha256']}  {item['path']}" for item in verdict["files"]]
    sums.append(f"{digest(index)}  candidate-index.json")
    (output / "SHA256SUMS.txt").write_text("\n".join(sorted(sums)) + "\n", encoding="ascii")
    archive = output.parent / f"FlowBridge-{version}-candidate-{source[:12]}.zip"
    require(not archive.exists(), "Refusing to replace an existing candidate archive")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(output.rglob("*")):
            if path.is_file():
                entry = zipfile.ZipInfo(path.relative_to(output).as_posix(), (2020, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 0o100644 << 16
                bundle.writestr(entry, path.read_bytes())
    archive.with_suffix(".zip.sha256").write_text(f"{digest(archive)}  {archive.name}\n", encoding="ascii")
    print(json.dumps({"archive": str(archive), "sha256": digest(archive),
                      "source_sha": source, "candidate_index_sha256": digest(index),
                      "hosted_candidate_valid": True, "release_accepted": False}, indent=2))
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    assemble(args.inputs, args.output, args.source_sha, args.run_id)


if __name__ == "__main__":
    main()
