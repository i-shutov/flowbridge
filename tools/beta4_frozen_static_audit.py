#!/usr/bin/env python3
"""Inventory the exact original beta.4 without executing or changing it."""
from __future__ import annotations

import io
import json
from pathlib import Path
import re
import sys
import zipfile

from beta3_frozen_static_audit import (
    NLOHMANN_REF, NSIS_ARCHIVE_SHA, NSIS_VERSION, PAYLOAD, REVIEWED_SOURCE_SHA, RUST_NOTICE_FILES,
    Rejected, cargo_notice_expression_counts, generated_msvc_settings, host_guard, license_notice_bytes,
    local_bytes, metadata_inventory, nsis_archive_inventory, payload_paths, pe_inventory, read_nsis_archive,
    require, sha,
)

VERSION = "0.3.0-beta.4"
RUN_ID = "46040903481"
SOURCE = "c8881dada43e3183a0340dc823105bdcdac71171"
TREE = "ce336e83bb724a65bf512e79e286c97fb0cb3190"
MANIFEST_SHA = "3542633d089aff80e379f30db8be6f301edae462f38f70ea07c5b8ba76011703"
INSTALLER_SHA = "e0e4491cd97b30aa52b52ce89a7a8396a2fc11902bec3e70bed8ebfd722450b0"
HARNESS_SHA = "46cd8970cf669e0be3493998aeec6ba30ecb464dd399d0c3cdd972444e193a32"
BUILD_METADATA_SHA = "31f01bf7f112c36e467d164e19cea59ef29d32e36114b0e2bb97da0556fb1cbd"
SBOM_SHA = "3ea9e447fb67467d922f4c9394d6f13dc85f56cd1fb1a6234c71bf0ed65260b1"
NSIS_LOG_SHA = "b789345374b8fa09fa953c961751c275c74ebf1422fe04a4fdc40eac835983af"
NSIS_COMPILER_SHA = "65343c225ec88393cc4453b0963caf63f763f42f48cb55736d51893ff2e29d4a"
BINARIES = {
    "FlowBridge.exe": "8317e93ecda430848cfe4e565daa80c90297c0a6ef66a9b8b60263f1666a837a",
    "flowbridge-cli.exe": "12dfc4ec1f605cfb41a69f574c32f68eaf4ddbe7a4a5eebec02a662c98b6b824",
    "flowbridge_ffi.dll": "a193b8c9e96ecbcd5c2a79722a09e7ca3a822ce406ec997c9ab475f022f2469a",
}
ATTRIBUTIONS = "third_party/nlohmann/ATTRIBUTIONS.txt"
NATIVE_REF = "pkg:generic/msvc-static-runtime"
NSIS_REF = "pkg:generic/nsis@" + NSIS_VERSION
NSIS_ENTRIES = {
    "pkg:generic/nsis-lzma-stub@3.13": "Stubs/lzma_solid-x86-unicode",
    "pkg:generic/nsis-system@3.13": "Plugins/x86-unicode/System.dll",
    "pkg:generic/nsis-langdll@3.13": "Plugins/x86-unicode/LangDLL.dll",
    "pkg:generic/nsis-nsdialogs@3.13": "Plugins/x86-unicode/nsDialogs.dll",
}
EXTERNAL_RUNTIMES = [
    "Windows OpenSSH client or explicitly selected local Microsoft-signed OpenSSH client",
    "Windows PowerShell and Microsoft.PowerShell.Security for OpenSSH Authenticode verification",
]
PHASE = "HOST_GUARD"


def distribution_inputs(archive: bytes, extracted: Path) -> dict[str, str]:
    require(sha(archive) == NSIS_ARCHIVE_SHA, "nsis_archive_sha256")
    result = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for relative in ("Bin/makensis.exe", "COPYING", *NSIS_ENTRIES.values()):
            allowed = {relative.casefold(), f"nsis-{NSIS_VERSION}/{relative}".casefold()}
            entries = [entry for entry in bundle.infolist() if entry.filename.casefold() in allowed]
            require(len(entries) == 1 and 0 < entries[0].file_size <= 10_000_000, "nsis_archive_file_identity")
            entry = entries[0]
            bundled = bundle.read(entry)
            require(local_bytes(extracted / entry.filename, 10_000_000) == bundled, "nsis_extracted_input_bytes")
            result[relative] = sha(bundled)
    return result


def native_provenance(build: Path, metadata: dict) -> dict:
    observed = generated_msvc_settings(build)
    cache = local_bytes(build / "CMakeCache.txt", 1048576)
    require(re.search(rb"^FLOWBRIDGE_EXPLICIT_BETA_ONLY:BOOL=ON\r?$", cache, re.M) is not None,
            "explicit_only_cache_flag")
    generators = re.findall(rb"^CMAKE_GENERATOR:INTERNAL=(Visual Studio [ -~]+)\r?$", cache, re.M)
    require(len(generators) == 1 and re.search(rb"^CMAKE_GENERATOR_PLATFORM:INTERNAL=x64\r?$", cache, re.M),
            "cmake_native_x64_generator")
    expected = {
        "cmake": observed["cmake"], "generator": generators[0].decode("ascii"), "generator_platform": "x64",
        "cmake_cache_sha256": sha(cache), "cmake_compiler_config_sha256": observed["cmake_cxx_compiler_sha256"],
        "msvc_cxx_compiler_version": observed["msvc_cxx_compiler_version"],
        "generated_targets": {name: {
            "msvc_runtime_library": value["runtime_library"], "platform_toolset": value["platform_toolset"],
            "windows_target_platform_version": value["windows_target_platform_version"],
            "vcxproj_sha256": value["project_sha256"],
        } for name, value in observed["targets"].items()},
        "rust_crt_static_configured_targets": ["flowbridge-cli", "flowbridge-ffi"],
        "static_linker_members_verified": False,
    }
    require(metadata == expected, "cmake_sbom_input_chain")
    return observed


def coverage(candidate: Path, files: dict[str, bytes]) -> dict:
    meta = json.loads(files["BUILD-METADATA.json"])
    bom = json.loads(files["SBOM.cdx.json"])
    rustc = meta["rustc"]
    rust = re.fullmatch(r"rustc (1\.100\.0) \([0-9a-f]{9} \d{4}-\d{2}-\d{2}\)", rustc)
    require(rust is not None, "licensed_rustc_version")
    inventory = license_notice_bytes(files["licenses/THIRD_PARTY_NOTICES.txt"], meta["license_inventory"],
                                     rustc, version=VERSION, nlohmann_attributions=True)
    source_pins = {**REVIEWED_SOURCE_SHA,
                   ATTRIBUTIONS: "6ec3651ad7ed93ded516aee4c39fb9c36596d44cd851ce66d1e45177bc58b08c"}
    sources = {name: local_bytes(candidate / name, 1048576) for name in source_pins}
    require(all(sha(sources[name]) == expected for name, expected in source_pins.items()), "reviewed_source_sha256")
    require(files["LICENSE"] == sources["LICENSE"], "project_license_source_bytes")
    require(inventory[(NLOHMANN_REF, "LICENSE.MIT")] == files["licenses/nlohmann-json-LICENSE.MIT"]
            == sources["third_party/nlohmann/LICENSE.MIT"], "nlohmann_license_source_bytes")
    require(inventory[(NLOHMANN_REF, "ATTRIBUTIONS.txt")] == sources[ATTRIBUTIONS],
            "nlohmann_attributions_source_bytes")

    rust_ref = "pkg:generic/rust-standard-library@" + rust.group(1)
    native = {item["purl"]: item for item in bom["components"] if not item["purl"].startswith("pkg:cargo/")}
    require(set(native) == {NLOHMANN_REF, NSIS_REF, rust_ref, NATIVE_REF, *NSIS_ENTRIES}, "non_cargo_sbom_coverage")
    require(native[NLOHMANN_REF]["hashes"] == [{"alg": "SHA-256", "content":
            sha(sources["third_party/nlohmann/json.hpp"])}], "nlohmann_sbom_source_bytes")
    edges = {item["ref"]: set(item["dependsOn"]) for item in bom["dependencies"]}
    require(edges.get(NSIS_REF) == NSIS_ENTRIES.keys()
            and all(NATIVE_REF in edges.get(f"pkg:cargo/{name}@{VERSION}", ())
                    for name in ("flowbridge-cli", "flowbridge-ffi")), "native_sbom_dependencies")

    root = candidate.parent.parent
    archive = read_nsis_archive((candidate.parent / "nsis-3.13.zip", root.parent / "toolchains/nsis-3.13.zip",
                                 root / "run-45986630920-1/nsis-3.13.zip"))
    upstream = nsis_archive_inventory(archive, inventory[("NSIS installer runtime", "COPYING")])
    inputs = distribution_inputs(archive, candidate.parent / "candidate-nsis-toolchain")
    require(inputs["Bin/makensis.exe"] == NSIS_COMPILER_SHA, "nsis_compiler_sha256")
    require(all(native[ref]["name"] == name
                and native[ref]["hashes"] == [{"alg": "SHA-256", "content": inputs[name]}]
                for ref, name in NSIS_ENTRIES.items()), "nsis_sbom_resource_hashes")
    require(meta["windows_nsis_distribution_members"] == {
        "compiler_relative_path": "Bin/makensis.exe", "compiler_sha256": NSIS_COMPILER_SHA,
        "compiler_version": NSIS_VERSION, "copying_sha256": inputs["COPYING"],
        "resource_sha256": {name: inputs[name] for name in NSIS_ENTRIES.values()},
        "compiler_passed_explicitly": True, "installer_embedded_members_verified": False,
    }, "nsis_build_metadata_input_chain")
    require(meta["windows_managed_ssh_external_runtimes"] == EXTERNAL_RUNTIMES, "external_runtime_scope")
    build = candidate / "build/windows-explicit-beta"
    return {
        "notice_file_bytes_verified": len(inventory),
        "cargo_declared_license_expression_counts": cargo_notice_expression_counts(bom["components"], inventory),
        "nlohmann_attributions_sha256": sha(sources[ATTRIBUTIONS]),
        "rust_standard_library_notice_sha256": {name: sha(inventory[(rustc, name)]) for name in RUST_NOTICE_FILES},
        "nsis": {**upstream, "archive_and_extracted_inputs_sha256": inputs, "compile_log_sha256": NSIS_LOG_SHA},
        "generated_msvc_settings": native_provenance(build, meta["windows_native_build_inputs"]),
        "static_msvc_runtime_separately_identified_in_sbom": True,
        "external_runtime_dependencies_identified_by_source": EXTERNAL_RUNTIMES,
        "non_cargo_sbom_refs": sorted(native), "runtime_execution_observed": False,
        "license_obligations_accepted": False, "live_authenticode_verified": False,
    }


def audit(candidate: Path) -> dict:
    global PHASE
    PHASE = "EXACT_CANDIDATE_IDENTITY"
    raw = local_bytes(candidate / "build/verification/explicit-beta-package.json", 65536)
    require(sha(raw) == MANIFEST_SHA, "manifest_sha256")
    manifest = json.loads(raw)
    require(manifest.get("schema") == "flowbridge-explicit-beta-windows-qa-package-v1"
            and manifest.get("source_sha") == SOURCE and manifest.get("source_tree_sha") == TREE
            and manifest.get("candidate") == VERSION and manifest.get("workflow_run_id") == RUN_ID,
            "manifest_identity")
    require(manifest.get("explicit_socks_only") is True
            and manifest.get("gui_protected_ui_compiled_disabled") is True and manifest.get("wfp_native_gate") == "NO_GO"
            and manifest.get("profile_namespace") == manifest.get("uninstall_registration") == "FlowBridgeExplicitBeta",
            "manifest_explicit_scope")
    for key in ("signed", "publisher_release_approved", "driver_included", "capture_helper_included",
                "system_service_included", "system_dns_or_proxy_mutated", "independent_reviewer_passed",
                "app_specific_interception", "udp_or_quic_proxied"):
        require(manifest.get(key) is False, "manifest_acceptance_promoted")
    PHASE = "EXACT_PAYLOAD_AND_PE"
    records = {item["path"]: item for item in manifest["payload"]}
    stage = candidate / "build/explicit-beta-payload"
    require(set(records) == PAYLOAD and len(manifest["payload"]) == len(PAYLOAD)
            and payload_paths(stage) == PAYLOAD, "payload_allowlist")
    files = {name: local_bytes(stage / name) for name in sorted(PAYLOAD)}
    require(all(sha(data) == records[name]["sha256"] and len(data) == records[name]["bytes"]
                for name, data in files.items()), "payload_bytes")
    require(all(sha(files[name]) == expected for name, expected in BINARIES.items()), "binary_sha256")
    images = {name: {"sha256": expected, **pe_inventory(files[name])} for name, expected in BINARIES.items()}
    build = candidate / "build/windows-explicit-beta"
    for name, path, expected, record in (
        ("installer", candidate / f"artifacts/FlowBridge-{VERSION}-windows-x64-setup.exe", INSTALLER_SHA,
         {"sha256": manifest["installer_sha256"], "bytes": manifest["installer_bytes"]}),
        ("qa_harness", build / "Release/FlowBridgeNativeSmoke.exe", HARNESS_SHA, manifest["qa_harness"]),
    ):
        data = local_bytes(path)
        require(sha(data) == expected == record["sha256"] and len(data) == record["bytes"], "installer_or_harness_sha256")
        images[name] = {"sha256": expected, **pe_inventory(data, installer=name == "installer")}
    require(images["installer"]["machine"] == manifest["bootstrapper_pe_machine"] == "0x014c",
            "installer_bootstrapper_machine")
    PHASE = "SBOM_NOTICES_AND_NATIVE_INPUTS"
    metadata = metadata_inventory(files, local_bytes(candidate / "Cargo.lock", 1048576),
                                  local_bytes(candidate / "packaging/explicit-beta.json", 65536),
                                  version=VERSION, source_sha=SOURCE)
    require(metadata["sbom_sha256"] == manifest["sbom_sha256"] == SBOM_SHA
            and metadata["build_metadata_sha256"] == manifest["build_metadata_sha256"] == BUILD_METADATA_SHA
            and sha(local_bytes(build / "nsis-compile.log", 1_048_576)) == manifest["nsis_compile_log_sha256"] == NSIS_LOG_SHA,
            "manifest_metadata_chain")
    return {
        "schema": "flowbridge-frozen-beta4-static-inventory-v1", "status": "TECHNICAL_STATIC_INVENTORY_COMPLETE",
        "source_run_id": RUN_ID, "source_sha": SOURCE, "source_tree_sha": TREE, "manifest_sha256": MANIFEST_SHA,
        "payload_files_verified": len(files), "metadata": metadata, "pe_images": images,
        "notice_coverage": coverage(candidate, files), "candidate_executed": False, "candidate_changed": False,
        "installer_executed": False, "win10_accessed": False,
        "a5_accepted": False, "a6_accepted": False, "a7_approved": False,
    }


def main() -> int:
    try:
        host_guard()
        result = audit(Path(f"C:/FlowBridge/private-candidates/run-beta4-{RUN_ID}-1/candidate"))
    except Exception as exc:
        result = {"schema": "flowbridge-frozen-beta4-static-inventory-v1", "status": "BLOCKED",
                  "phase": PHASE, "error_code": str(exc) if isinstance(exc, Rejected) else "static_inventory_failed",
                  "a5_accepted": False, "a6_accepted": False, "a7_approved": False}
    print("BETA4_STATIC_INVENTORY " + json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "TECHNICAL_STATIC_INVENTORY_COMPLETE" else 1


if __name__ == "__main__":
    sys.exit(main())
