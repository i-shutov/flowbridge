#!/usr/bin/env python3
"""Read-only inventory of the frozen private beta.3 on the pinned Win11 host.

Never executes a candidate, loads a DLL, invokes an installer, writes candidate
files or changes Windows settings. PE decoding follows Microsoft's PE Format:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
The result is a bounded inventory, not security, legal or release acceptance.
"""
from __future__ import annotations

import csv
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import tomllib

VERSION = "0.3.0-beta.3"
SOURCE = "c6ead0f31de4c118453913d733f537ba421af616"
TREE = "19df7a94071f38be6b8aa3530e1ded7a954a02a8"
MANIFEST_SHA = "f6a94e5e8a87e571d63604ff3b2e417bf21e2e2758343171c587a43717318c99"
INSTALLER_SHA = "6408c0bf595b0ae61a4fc05db17421dc4b03dcda241f3c1f1f997ab6583eec5b"
HARNESS_SHA = "d41905fdcb2fc5f77e042d61c9aac5d640b23ca60ea0cf0965a4567dc9b105ff"
BINARIES = {
    "FlowBridge.exe": "8137a43a27eae62ba3988baeb5dffde0ee03fa983c96e8440480d77b1072b4d0",
    "flowbridge-cli.exe": "10182b2d58d9d0728f301afe3deb21be33b7aff9b99c627f4f37507bec7b70ab",
    "flowbridge_ffi.dll": "cb933d0a0c312932d80c60ece25549a749f9664807e225dd339da2e57dad5b4e",
}
PAYLOAD = set(BINARIES) | {
    "LICENSE", "README.txt", "SBOM.cdx.json", "BUILD-METADATA.json",
    "licenses/nlohmann-json-LICENSE.MIT", "licenses/THIRD_PARTY_NOTICES.txt",
    "resources/presets.json", "examples/direct.json", "examples/ssh-socks.json",
    "examples/chain.json",
}
PHASE = "HOST_GUARD"


class Rejected(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Rejected(code)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def no_links(path: Path) -> None:
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode)
                and not (getattr(info, "st_file_attributes", 0) & 0x400), "local_reparse_point")


def local_bytes(path: Path, limit: int = 134217728) -> bytes:
    no_links(path)
    require(stat.S_ISREG(path.lstat().st_mode), "regular_file_required")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(0 < len(data) <= limit, "local_file_size")
    return data


def payload_paths(stage: Path) -> set[str]:
    # Reject a redirected top directory BEFORE enumeration: followlinks=False
    # only controls descendants and is not a guard for the walk's starting path.
    no_links(stage)
    require(stat.S_ISDIR(stage.lstat().st_mode), "payload_directory_required")
    actual = set()
    def walk_error(_error):
        raise Rejected("payload_enumeration_failed")
    for folder, directories, filenames in os.walk(stage, followlinks=False, onerror=walk_error):
        for name in directories + filenames:
            path = Path(folder) / name
            no_links(path)
            relative = path.relative_to(stage).as_posix()
            require(relative in ({"licenses", "resources", "examples"} if name in directories else PAYLOAD),
                    "payload_disk_allowlist")
        actual.update((Path(folder) / name).relative_to(stage).as_posix() for name in filenames)
    return actual


def pe_inventory(data: bytes, *, installer: bool = False) -> dict:
    """Decode directory entries bounded by file-backed sections, not virtual size."""
    def unpack(fmt: str, offset: int):
        require(0 <= offset <= len(data) - struct.calcsize(fmt), "pe_bounds")
        return struct.unpack_from(fmt, data, offset)

    require(len(data) >= 64 and data[:2] == b"MZ", "pe_dos_header")
    nt, = unpack("<I", 0x3c)
    require(nt >= 64 and data[nt:nt + 4] == b"PE\0\0", "pe_signature")
    machine, count = unpack("<HH", nt + 4)
    require(machine in ({0x14c, 0x8664} if installer else {0x8664}), "pe_machine")
    require(0 < count <= 96, "pe_section_count")
    optional_size, = unpack("<H", nt + 20)
    optional = nt + 24
    magic, = unpack("<H", optional)
    require(magic == (0x20b if machine == 0x8664 else 0x10b), "pe_optional_magic")
    directory_offset = 112 if magic == 0x20b else 96
    require(optional_size >= directory_offset and optional + optional_size <= len(data), "pe_optional_size")
    directory_count, = unpack("<I", optional + directory_offset - 4)
    require(directory_count <= (optional_size - directory_offset) // 8, "pe_directory_count")
    header_size, = unpack("<I", optional + 60)
    flags, = unpack("<H", optional + 70)
    image_base, = unpack("<Q" if magic == 0x20b else "<I", optional + (24 if magic == 0x20b else 28))
    section_table = optional + optional_size
    require(section_table + count * 40 <= header_size <= len(data), "pe_header_size")
    sections = []
    for index in range(count):
        address, raw_size, pointer = unpack("<III", section_table + index * 40 + 12)
        require(raw_size == 0 or (pointer >= header_size and pointer + raw_size <= len(data)), "pe_section_bounds")
        if raw_size:
            require(address >= header_size, "pe_section_header_overlap")
            for other_address, other_size, other_pointer in sections:
                require(address + raw_size <= other_address or other_address + other_size <= address,
                        "pe_section_rva_overlap")
                require(pointer + raw_size <= other_pointer or other_pointer + other_size <= pointer,
                        "pe_section_file_overlap")
            sections.append((address, raw_size, pointer))

    def rva(address: int, size: int) -> int:
        require(address >= 0 and size > 0, "pe_rva_invalid")
        if address + size <= header_size:
            return address
        matches = [pointer + address - start for start, length, pointer in sections
                   if start <= address and address + size <= start + length]
        require(len(matches) == 1, "pe_rva_not_file_backed")
        return matches[0]

    def directory(index: int) -> tuple[int, int]:
        if index >= directory_count:
            return 0, 0
        address, size = unpack("<II", optional + directory_offset + index * 8)
        require(bool(address) == bool(size), "pe_directory_pair")
        return address, size

    def dll_name(address: int) -> str:
        name = bytearray()
        for index in range(260):
            value = data[rva(address + index, 1)]
            if value == 0:
                require(re.fullmatch(rb"[A-Za-z0-9_.-]+\.dll", bytes(name), re.I) is not None,
                        "pe_import_name")
                return name.decode("ascii").lower()
            name.append(value)
        raise Rejected("pe_import_name_unterminated")

    def imports(index: int, width: int) -> list[str]:
        address, size = directory(index)
        if not address:
            return []
        require(width <= size <= 131072, "pe_import_directory_size")
        rva(address, size)
        names = []
        for offset in range(0, size - width + 1, width):
            record = unpack("<" + "I" * (width // 4), rva(address + offset, width))
            if not any(record):
                require(len(names) == len(set(names)), "pe_duplicate_import")
                return sorted(names)
            require(len(names) < 128, "pe_import_limit")
            if index == 13:
                require(record[0] in (0, 1), "pe_delay_attributes")
                address_name = record[1] if record[0] == 1 else record[1] - image_base
            else:
                address_name = record[3]
            require(address_name > 0, "pe_import_name_missing")
            names.append(dll_name(address_name))
        raise Rejected("pe_import_directory_unterminated")

    direct, delayed = imports(1, 20), imports(13, 32)
    require(bool(direct), "pe_direct_imports_missing")
    certificate, certificate_size = directory(4)  # File offset, NOT an RVA.
    if certificate:
        require(certificate % 8 == 0 and certificate + certificate_size <= len(data), "pe_certificate_bounds")
    names = direct + delayed
    return {
        "machine": f"0x{machine:04x}", "direct_imports": direct, "delay_imports": delayed,
        "declared_dll_characteristics": {"dynamic_base": bool(flags & 0x40),
            "nx_compat": bool(flags & 0x100), "high_entropy_va": bool(flags & 0x20),
            "guard_cf": bool(flags & 0x4000)},
        "embedded_certificate_table_present": bool(certificate),
        "authenticode_verified": False,
        "direct_or_delay_msvc_runtime_imports": sorted({name for name in names
            if name.startswith(("vcruntime", "msvcp", "msvcr", "api-ms-win-crt-")) or name == "ucrtbase.dll"}),
        "recursive_or_dynamic_loads_inspected": False,
    }


def metadata_inventory(files: dict[str, bytes], lock_bytes: bytes, contract_bytes: bytes) -> dict:
    metadata = json.loads(files["BUILD-METADATA.json"])
    bom = json.loads(files["SBOM.cdx.json"])
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    contract = json.loads(contract_bytes)
    require(metadata.get("schema") == "flowbridge-explicit-beta-build-metadata-v1"
            and metadata.get("source_sha") == SOURCE and metadata.get("version") == VERSION
            and metadata.get("platform") == "windows", "metadata_identity")
    require(metadata.get("targets") == ["x86_64-pc-windows-msvc"]
            and metadata.get("shipped_cargo_roots") == ["flowbridge-cli", "flowbridge-ffi"], "metadata_scope")
    for key in ("binary_linkage_reviewed", "independent_license_review_passed", "vulnerability_audit_performed",
                "publisher_release_approved", "driver_included", "system_extension_included"):
        require(metadata.get(key) is False, "metadata_acceptance_promoted")
    require(metadata.get("explicit_socks_only") is True, "metadata_explicit_only")
    require(metadata.get("cargo_lock_sha256") == sha(lock_bytes)
            and metadata.get("version_contract_sha256") == sha(contract_bytes)
            and metadata.get("sbom_sha256") == sha(files["SBOM.cdx.json"])
            and metadata.get("notices_sha256") == sha(files["licenses/THIRD_PARTY_NOTICES.txt"]), "metadata_hash_chain")
    require(contract.get("version") == VERSION and contract.get("release_approved") is False, "contract_identity")
    require(bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion") == "1.5"
            and bom.get("metadata", {}).get("component", {}).get("version") == VERSION, "bom_identity")
    properties = {item["name"]: item["value"] for item in bom["metadata"]["properties"]}
    require(properties.get("flowbridge:source_sha") == SOURCE, "bom_source")
    components = bom.get("components")
    require(type(components) is list and 0 < len(components) <= 256
            and metadata.get("component_count") == len(components), "bom_component_count")
    pins = {(item["name"], item["version"]): item for item in lock["package"]}
    refs = set()
    cargo_count, external_cargo = 0, set()
    for item in components:
        ref = item.get("bom-ref")
        require(type(ref) is str and ref == item.get("purl") and ref not in refs, "bom_duplicate_or_missing_ref")
        refs.add(ref)
        require(type(item.get("licenses")) is list and len(item["licenses"]) > 0, "bom_license_metadata_missing")
        if ref.startswith("pkg:cargo/"):
            pin = pins.get((item.get("name"), item.get("version")))
            require(pin is not None and ref == f"pkg:cargo/{pin['name']}@{pin['version']}", "bom_lock_identity")
            cargo_count += 1
            if pin.get("checksum"):
                require(item.get("hashes") == [{"alg": "SHA-256", "content": pin["checksum"]}], "bom_lock_checksum")
                external_cargo.add(ref)
            else:
                require(pin["name"].startswith("flowbridge-") and pin["version"] == VERSION, "bom_local_package")
    for edge in bom.get("dependencies", []):
        require(edge.get("ref") in refs and all(child in refs for child in edge.get("dependsOn", [])), "bom_dependency_ref")
    inventory = metadata.get("license_inventory")
    require(type(inventory) is list and 0 < len(inventory) <= 256, "license_inventory_missing")
    inventories = set()
    license_files = 0
    for entry in inventory:
        require(type(entry.get("component")) is str and entry["component"] not in inventories, "license_inventory_duplicate")
        inventories.add(entry["component"])
        require(type(entry.get("files")) is list and 0 < len(entry["files"]) <= 32, "license_inventory_files")
        for item in entry["files"]:
            require(type(item.get("name")) is str and type(item.get("sha256")) is str
                    and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None, "license_inventory_hash")
            license_files += 1
    require(external_cargo <= inventories
            and {"pkg:github/nlohmann/json@v3.11.3", "NSIS installer runtime", metadata.get("rustc")} <= inventories,
            "license_inventory_coverage")
    return {"components": len(components), "cargo_components": cargo_count,
        "external_cargo_lock_checksums_verified": len(external_cargo),
        "license_inventory_entries": len(inventory), "license_file_hash_records": license_files,
        "sbom_sha256": sha(files["SBOM.cdx.json"]), "notices_sha256": sha(files["licenses/THIRD_PARTY_NOTICES.txt"]),
        "build_metadata_sha256": sha(files["BUILD-METADATA.json"]),
        "resolved_graph_recomputed": False, "license_text_obligations_reviewed": False,
        "current_vulnerability_database_checked": False}


def audit(candidate: Path) -> dict:
    global PHASE
    PHASE = "FROZEN_IDENTITY"
    raw_manifest = local_bytes(candidate / "build/verification/explicit-beta-package.json", 65536)
    require(sha(raw_manifest) == MANIFEST_SHA, "manifest_sha256")
    manifest = json.loads(raw_manifest)
    require(manifest.get("source_sha") == SOURCE and manifest.get("source_tree_sha") == TREE
            and manifest.get("candidate") == VERSION and manifest.get("workflow_run_id") == "45986630920",
            "manifest_identity")
    require(manifest.get("explicit_socks_only") is True and manifest.get("gui_protected_ui_compiled_disabled") is True,
            "manifest_explicit_scope")
    for key in ("signed", "publisher_release_approved", "driver_included", "capture_helper_included",
                "system_service_included", "system_dns_or_proxy_mutated", "independent_reviewer_passed"):
        require(manifest.get(key) is False, "manifest_acceptance_promoted")
    payload = manifest.get("payload")
    require(type(payload) is list and len(payload) == len(PAYLOAD), "payload_count")
    records = {item["path"]: item for item in payload}
    require(set(records) == PAYLOAD, "payload_allowlist")
    stage = candidate / "build/explicit-beta-payload"
    require(payload_paths(stage) == PAYLOAD, "payload_disk_allowlist")
    files = {}
    for name in sorted(PAYLOAD):
        data = local_bytes(stage / name)
        require(sha(data) == records[name]["sha256"] and len(data) == records[name]["bytes"], "payload_bytes")
        if name in BINARIES:
            require(sha(data) == BINARIES[name], "binary_sha256")
        files[name] = data
    PHASE = "SBOM_AND_NOTICES"
    metadata = metadata_inventory(files, local_bytes(candidate / "Cargo.lock", 1048576),
                                  local_bytes(candidate / "packaging/explicit-beta.json", 65536))
    require(metadata["sbom_sha256"] == manifest["sbom_sha256"]
            and metadata["build_metadata_sha256"] == manifest["build_metadata_sha256"], "manifest_metadata_chain")
    PHASE = "PE_STATIC_INVENTORY"
    images = {name: {"sha256": BINARIES[name], **pe_inventory(files[name])} for name in BINARIES}
    installer = local_bytes(candidate / "artifacts/FlowBridge-0.3.0-beta.3-windows-x64-setup.exe")
    require(sha(installer) == INSTALLER_SHA and len(installer) == manifest["installer_bytes"], "installer_sha256")
    images["installer"] = {"sha256": INSTALLER_SHA, **pe_inventory(installer, installer=True)}
    harness = local_bytes(candidate / "build/windows-explicit-beta/Release/FlowBridgeNativeSmoke.exe")
    require(sha(harness) == HARNESS_SHA and len(harness) == manifest["qa_harness"]["bytes"], "harness_sha256")
    images["qa_harness"] = {"sha256": HARNESS_SHA, **pe_inventory(harness)}
    return {"schema": "flowbridge-frozen-beta3-static-inventory-v1", "status": "TECHNICAL_STATIC_INVENTORY_COMPLETE",
        "source_sha": SOURCE, "source_tree_sha": TREE, "manifest_sha256": MANIFEST_SHA,
        "payload_files_verified": len(files), "metadata": metadata, "pe_images": images,
        "candidate_executed": False, "candidate_changed": False, "installer_executed": False,
        "win10_accessed": False, "a5_accepted": False, "a6_accepted": False, "a7_approved": False}


def host_guard() -> None:
    require(os.name == "nt" and sys.maxsize > 2**32, "native_windows_x64_required")
    version = sys.getwindowsversion()
    require(version.product_type == 1 and version.build >= 22000
            and socket.gethostname().casefold() == "vm-326272"
            and os.environ.get("RUNNER_NAME") == "win11-flowbridge"
            and ctypes.windll.shell32.IsUserAnAdmin(), "pinned_win11_runner_required")
    process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    query = kernel.IsWow64Process2
    query.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort)]
    query.restype = ctypes.c_int
    require(query(ctypes.c_void_p(-1), ctypes.byref(process_machine), ctypes.byref(native_machine))
            and process_machine.value == 0 and native_machine.value == 0x8664, "native_amd64_required")
    identity = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/whoami.exe"),
        "/user", "/fo", "csv", "/nh"], check=True, capture_output=True, text=True, timeout=10)
    account, _ = next(csv.reader([identity.stdout.strip()]))
    require(account.casefold() == "vm-326272\\admin", "pinned_account_required")


def main() -> int:
    try:
        host_guard()
        result = audit(Path("C:/FlowBridge/private-candidates/run-45986630920-1/candidate"))
        code = 0
    except Exception as error:
        result = {"schema": "flowbridge-frozen-beta3-static-inventory-v1", "status": "BLOCKED",
            "phase": PHASE, "error_code": str(error) if isinstance(error, Rejected) else "static_inventory_failed",
            "a5_accepted": False, "a6_accepted": False, "a7_approved": False}
        code = 1
    print("BETA3_STATIC_INVENTORY " + json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
