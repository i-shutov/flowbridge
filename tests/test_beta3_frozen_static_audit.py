"""Adversarial parsing checks; these do not replace the native frozen-file run."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import zipfile

SPEC = importlib.util.spec_from_file_location("audit", Path(__file__).resolve().parents[1] / "tools/beta3_frozen_static_audit.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def pe(*, x86=False, delay=False, legacy_delay=False):
    data = bytearray(2048)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 128)
    data[128:132] = b"PE\0\0"
    optional_size, directory = (224, 96) if x86 else (240, 112)
    struct.pack_into("<HH", data, 132, 0x14c if x86 else 0x8664, 1)
    struct.pack_into("<H", data, 148, optional_size)
    start = 152
    struct.pack_into("<H", data, start, 0x10b if x86 else 0x20b)
    struct.pack_into("<I" if x86 else "<Q", data, start + (28 if x86 else 24), 0x400000)
    struct.pack_into("<I", data, start + 60, 512)
    struct.pack_into("<H", data, start + 70, 0x4160)
    struct.pack_into("<I", data, start + directory - 4, 16)
    struct.pack_into("<II", data, start + directory + 8, 0x1000, 40)
    section = start + optional_size
    struct.pack_into("<IIII", data, section + 8, 1536, 0x1000, 1536, 512)
    struct.pack_into("<IIIII", data, 512, 0, 0, 0, 0x1080, 0)
    data[640:653] = b"KERNEL32.dll\0"
    if delay:
        struct.pack_into("<II", data, start + directory + 13 * 8, 0x1100, 64)
        struct.pack_into("<II", data, 768, 0 if legacy_delay else 1,
                         0x401180 if legacy_delay else 0x1180)
        data[896:911] = b"VCRUNTIME1.dll\0"
    return data


def metadata_fixture():
    encode = lambda value: json.dumps(value).encode()
    lock = b'[[package]]\nname="sample"\nversion="1.0.0"\nchecksum="' + b'a' * 64 + b'"\n'
    contract = encode({"version": audit.VERSION, "release_approved": False})
    ref = "pkg:cargo/sample@1.0.0"
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"version": audit.VERSION},
            "properties": [{"name": "flowbridge:source_sha", "value": audit.SOURCE}]},
        "components": [{"name": "sample", "version": "1.0.0", "bom-ref": ref, "purl": ref,
            "licenses": [{"expression": "MIT"}], "hashes": [{"alg": "SHA-256", "content": "a" * 64}]}],
        "dependencies": [{"ref": ref, "dependsOn": []}]}
    files = {"SBOM.cdx.json": encode(bom), "licenses/THIRD_PARTY_NOTICES.txt": b"test notice"}
    meta = {"schema": "flowbridge-explicit-beta-build-metadata-v1", "source_sha": audit.SOURCE,
        "version": audit.VERSION, "platform": "windows", "targets": ["x86_64-pc-windows-msvc"],
        "shipped_cargo_roots": ["flowbridge-cli", "flowbridge-ffi"], "explicit_socks_only": True,
        "cargo_lock_sha256": audit.sha(lock), "version_contract_sha256": audit.sha(contract),
        "sbom_sha256": audit.sha(files["SBOM.cdx.json"]), "notices_sha256": audit.sha(files["licenses/THIRD_PARTY_NOTICES.txt"]),
        "component_count": 1, "rustc": "rustc test",
        "license_inventory": [{"component": name, "files": [{"name": "LICENSE", "sha256": "b" * 64}]}
            for name in (ref, "pkg:github/nlohmann/json@v3.11.3", "NSIS installer runtime", "rustc test")]}
    for key in ("binary_linkage_reviewed", "independent_license_review_passed", "vulnerability_audit_performed",
                "publisher_release_approved", "driver_included", "system_extension_included"):
        meta[key] = False
    files["BUILD-METADATA.json"] = encode(meta)
    return files, lock, contract


def notice_fixture():
    ref = "pkg:cargo/sample@1.0.0"
    rustc = "rustc 1.100.0 (ab0123456 2026-11-27)"
    header = (f"FlowBridge {audit.VERSION} explicit beta — resolved component notices\n"
              "Targets: x86_64-pc-windows-msvc\n"
              "Includes production and build inputs of the shipped Cargo roots; exact binary retention is not asserted.\n"
              "Externally installed OpenSSH and OS frameworks are not redistributed by this package.\n").encode()
    fixture = {
        ref: [("LICENSE-APACHE", b"first\n\n--- LICENSE-MIT ---\nembedded marker\r\n",
               f"\n{'=' * 72}\n{ref}\n\n--- LICENSE-APACHE ---\n"),
              ("LICENSE-MIT", b"second\r\n", "\n--- LICENSE-MIT ---\n")],
        audit.NLOHMANN_REF: [("LICENSE.MIT", b"nlohmann MIT",
                            "\n=== nlohmann/json 3.11.3 — vendored Windows GUI header ===\n")],
        "NSIS installer runtime": [("COPYING", b"NSIS copying", "\n=== NSIS installer runtime distribution COPYING ===\n")],
        rustc: [(name, ("actual text " + name).encode(), f"\n=== Rust runtime / {name} ===\n")
                for name in audit.RUST_NOTICE_FILES],
    }
    notices = header + b"".join(heading.encode() + data + b"\n" for entries in fixture.values()
                                for _, data, heading in entries)
    inventory = [{"component": component, "files": [{"name": name, "sha256": audit.sha(data)}
                 for name, data, _ in entries]} for component, entries in fixture.items()]
    return notices, inventory, rustc


def nsis_fixture(*, duplicate=False):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as distribution:
        distribution.writestr("nsis-3.13/COPYING", b"NSIS copying")
        if duplicate:
            distribution.writestr("COPYING", b"NSIS copying")
        for name in audit.NSIS_PLUGIN_NAMES:
            distribution.writestr("nsis-3.13/Plugins/x86-unicode/" + name, pe(x86=True))
    return archive.getvalue()


class PeTests(unittest.TestCase):
    def test_x64_direct_imports_and_declared_flags(self):
        result = audit.pe_inventory(pe())
        self.assertEqual(result["direct_imports"], ["kernel32.dll"])
        self.assertEqual(result["delay_imports"], [])
        self.assertTrue(all(result["declared_dll_characteristics"].values()))
        self.assertFalse(result["authenticode_verified"])

    def test_x86_only_allowed_for_installer(self):
        with self.assertRaisesRegex(audit.Rejected, "pe_machine"):
            audit.pe_inventory(pe(x86=True))
        self.assertEqual(audit.pe_inventory(pe(x86=True), installer=True)["machine"], "0x014c")

    def test_repeated_dll_descriptors_retained_as_count(self):
        for delay in (False, True):
            data = pe(delay=delay)
            offset, width, index = (768, 32, 13) if delay else (512, 20, 1)
            data[offset + width:offset + 2 * width] = data[offset:offset + width]
            struct.pack_into("<I", data, 152 + 112 + index * 8 + 4, 3 * width)
            result = audit.pe_inventory(data)
            kind = "delay" if delay else "direct"
            with self.subTest(delay=delay):
                self.assertEqual(result[kind + "_import_descriptor_count"], 2)
                self.assertEqual(len(result[kind + "_imports"]), 1)

    def test_delay_rva_and_legacy_va(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                result = audit.pe_inventory(pe(x86=True, delay=True, legacy_delay=legacy), installer=True)
                self.assertEqual(result["delay_imports"], ["vcruntime1.dll"])

    def test_rejects_unterminated_and_truncated_directories(self):
        for size in (20, 19, 1600):
            data = pe()
            struct.pack_into("<I", data, 152 + 112 + 12, size)
            with self.subTest(size=size), self.assertRaises(audit.Rejected):
                audit.pe_inventory(data)

    def test_rejects_virtual_only_rva(self):
        data = pe()
        struct.pack_into("<I", data, 152 + 240 + 8, 8192)
        struct.pack_into("<I", data, 524, 0x1800)
        with self.assertRaisesRegex(audit.Rejected, "pe_rva_not_file_backed"):
            audit.pe_inventory(data)

    def test_rejects_path_in_dll_name(self):
        data = pe()
        data[640:653] = b"C:/leak.dll\0\0\0"
        with self.assertRaisesRegex(audit.Rejected, "pe_import_name"):
            audit.pe_inventory(data)

    def test_rejects_invalid_delay_attributes(self):
        data = pe(delay=True)
        struct.pack_into("<I", data, 768, 2)
        with self.assertRaisesRegex(audit.Rejected, "pe_delay_attributes"):
            audit.pe_inventory(data)

    def test_certificate_address_is_file_offset(self):
        data = pe()
        struct.pack_into("<II", data, 152 + 112 + 4 * 8, 1800, 16)
        self.assertTrue(audit.pe_inventory(data)["embedded_certificate_table_present"])
        struct.pack_into("<II", data, 152 + 112 + 4 * 8, 2048, 16)
        with self.assertRaisesRegex(audit.Rejected, "pe_certificate_bounds"):
            audit.pe_inventory(data)

    def test_rejects_ambiguous_overlapping_sections(self):
        data = pe()
        struct.pack_into("<H", data, 134, 2)
        data[432:472] = data[392:432]
        with self.assertRaisesRegex(audit.Rejected, "pe_section_rva_overlap"):
            audit.pe_inventory(data)


class InventoryTests(unittest.TestCase):
    def test_metadata_chain_and_license_coverage(self):
        report = audit.metadata_inventory(*metadata_fixture())
        self.assertEqual(report["external_cargo_lock_checksums_verified"], 1)
        self.assertFalse(report["license_text_obligations_reviewed"])

    def test_changed_notice_or_lock_rejected(self):
        for target in ("notice", "lock"):
            files, lock, contract = metadata_fixture()
            if target == "notice":
                files["licenses/THIRD_PARTY_NOTICES.txt"] += b"changed"
            else:
                lock += b"\n# changed\n"
            with self.subTest(target=target), self.assertRaisesRegex(audit.Rejected, "metadata_hash_chain"):
                audit.metadata_inventory(files, lock, contract)

    def test_promoted_acceptance_rejected(self):
        files, lock, contract = metadata_fixture()
        metadata = json.loads(files["BUILD-METADATA.json"])
        metadata["publisher_release_approved"] = True
        files["BUILD-METADATA.json"] = json.dumps(metadata).encode()
        with self.assertRaisesRegex(audit.Rejected, "metadata_acceptance_promoted"):
            audit.metadata_inventory(files, lock, contract)

    def test_missing_component_license_inventory_rejected(self):
        files, lock, contract = metadata_fixture()
        metadata = json.loads(files["BUILD-METADATA.json"])
        metadata["license_inventory"].pop(0)
        files["BUILD-METADATA.json"] = json.dumps(metadata).encode()
        with self.assertRaisesRegex(audit.Rejected, "license_inventory_coverage"):
            audit.metadata_inventory(files, lock, contract)

    def test_candidate_wrong_manifest_is_rejected_before_traversal(self):
        with mock.patch.object(audit, "local_bytes", return_value=b"wrong"), mock.patch.object(audit.os, "walk") as walk:
            with self.assertRaisesRegex(audit.Rejected, "manifest_sha256"):
                audit.audit(Path("unused"))
            walk.assert_not_called()

    def test_host_guard_failure_does_not_read_candidate_or_leak_exception(self):
        with mock.patch.object(audit, "host_guard", side_effect=OSError("private-host-path")), \
                mock.patch.object(audit, "audit") as inspect, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.main(), 1)
            inspect.assert_not_called()
        self.assertNotIn("private-host-path", output.getvalue())
        self.assertIn('"a6_accepted": false', output.getvalue())

    def test_symlink_and_oversize_file_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "value").write_bytes(b"123")
            with self.assertRaisesRegex(audit.Rejected, "local_file_size"):
                audit.local_bytes(root / "value", 2)
            try:
                (root / "link").symlink_to(root / "value")
            except OSError:
                return  # Windows without symlink privilege still runs size test.
            with self.assertRaisesRegex(audit.Rejected, "local_reparse_point"):
                audit.local_bytes(root / "link")

    def test_redirected_payload_root_rejected_before_enumeration(self):
        with mock.patch.object(audit, "no_links", side_effect=audit.Rejected("local_reparse_point")), \
                mock.patch.object(audit.os, "walk") as walk:
            with self.assertRaisesRegex(audit.Rejected, "local_reparse_point"):
                audit.payload_paths(Path("unused"))
            walk.assert_not_called()

    def test_unexpected_directory_rejected_before_descending(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "unexpected").mkdir()
            with self.assertRaisesRegex(audit.Rejected, "payload_disk_allowlist"):
                audit.payload_paths(Path(directory))

    def test_enumeration_errors_fail_closed(self):
        def bad_walk(path, **kwargs):
            kwargs["onerror"](PermissionError("private-path"))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(audit.os, "walk", side_effect=bad_walk):
            with self.assertRaisesRegex(audit.Rejected, "payload_enumeration_failed"):
                audit.payload_paths(Path(directory))


class NoticeCoverageTests(unittest.TestCase):
    def test_verified_sections_preserve_crlf_and_handle_embedded_heading(self):
        notices, inventory, rustc = notice_fixture()
        result = audit.license_notice_bytes(notices, inventory, rustc)
        self.assertEqual(len(result), 7)
        self.assertEqual(result[("pkg:cargo/sample@1.0.0", "LICENSE-MIT")], b"second\r\n")
        self.assertEqual(result[(audit.NLOHMANN_REF, "LICENSE.MIT")], b"nlohmann MIT")

    def test_notice_hash_detects_content_changes_and_trailing_text(self):
        notices, inventory, rustc = notice_fixture()
        for invalid in (notices.replace(b"second\r\n", b"other\r\n"), notices + b"added\n", notices[:-1]):
            with self.subTest(invalid=invalid[-12:]), self.assertRaises(audit.Rejected):
                audit.license_notice_bytes(invalid, inventory, rustc)

    def test_missing_or_reordered_license_section_is_rejected(self):
        notices, inventory, rustc = notice_fixture()
        inventory = [inventory[0], inventory[2], inventory[1], inventory[3]]
        with self.assertRaisesRegex(audit.Rejected, "notice_component_order"):
            audit.license_notice_bytes(notices, inventory, rustc)

    def test_nsis_copying_and_plugin_bytes_are_read_from_the_pinned_archive(self):
        archive = nsis_fixture()
        with mock.patch.object(audit, "NSIS_ARCHIVE_SHA", audit.sha(archive)):
            report = audit.nsis_archive_inventory(archive, b"NSIS copying")
            self.assertEqual(set(report["upstream_plugin_files"]), set(audit.NSIS_PLUGIN_NAMES))
            self.assertEqual(report["copying_sha256"], audit.sha(b"NSIS copying"))
            self.assertEqual(report["upstream_plugin_files"]["LangDLL.dll"]["direct_imports"], ["kernel32.dll"])
            self.assertFalse(report["embedded_plugin_bytes_verified"])
            with self.assertRaisesRegex(audit.Rejected, "nsis_copying_mismatch"):
                audit.nsis_archive_inventory(archive, b"changed")

    def test_nsis_pin_and_ambiguous_member_are_rejected(self):
        archive = nsis_fixture(duplicate=True)
        with self.assertRaisesRegex(audit.Rejected, "nsis_archive_sha256"):
            audit.nsis_archive_inventory(archive, b"NSIS copying")
        with mock.patch.object(audit, "NSIS_ARCHIVE_SHA", audit.sha(archive)), \
                self.assertRaisesRegex(audit.Rejected, "nsis_archive_file_identity"):
            audit.nsis_archive_inventory(archive, b"NSIS copying")

    def test_complete_notice_coverage_matches_public_scope_and_local_vendor_bytes(self):
        notices, inventory, rustc = notice_fixture()
        archive = nsis_fixture()
        ref = "pkg:cargo/sample@1.0.0"
        source = {"LICENSE": b"project", "third_party/nlohmann/LICENSE.MIT": b"nlohmann MIT",
                  "third_party/nlohmann/json.hpp": b"header"}
        components = [{"purl": ref, "hashes": [], "licenses": [{"expression": "MIT OR Apache-2.0"}]},
                      {"purl": audit.NLOHMANN_REF, "hashes": [{"alg": "SHA-256", "content": audit.sha(b"header")}]},
                      {"purl": "pkg:generic/nsis@3.13"}, {"purl": "pkg:generic/rust-standard-library@1.100.0"}]
        files = {"licenses/THIRD_PARTY_NOTICES.txt": notices, "licenses/nlohmann-json-LICENSE.MIT": b"nlohmann MIT",
                 "LICENSE": b"project", "SBOM.cdx.json": json.dumps({"components": components}).encode(),
                 "BUILD-METADATA.json": json.dumps({"license_inventory": inventory, "rustc": rustc}).encode()}
        with mock.patch.object(audit, "NSIS_ARCHIVE_SHA", audit.sha(archive)):
            report = audit.notice_coverage(files, source, archive)
            self.assertEqual(report["notice_file_bytes_verified"], 7)
            self.assertEqual(report["cargo_declared_license_expression_counts"], {"MIT OR Apache-2.0": 1})
            self.assertEqual(len(report["non_cargo_sbom_refs"]), 3)
            self.assertFalse(report["license_obligations_accepted"])
            files["licenses/nlohmann-json-LICENSE.MIT"] = b"modified"
            with self.assertRaisesRegex(audit.Rejected, "nlohmann_license_source_bytes"):
                audit.notice_coverage(files, source, archive)

    def test_generated_msvc_settings_report_release_static_runtime_and_toolchain(self):
        project = """<?xml version="1.0" encoding="utf-8"?>
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
    <PropertyGroup><WindowsTargetPlatformVersion>10.0.26100.0</WindowsTargetPlatformVersion></PropertyGroup>
    <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
        <PlatformToolset>v143</PlatformToolset>
    </PropertyGroup>
    <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
        <ClCompile><RuntimeLibrary>MultiThreaded</RuntimeLibrary></ClCompile>
    </ItemDefinitionGroup>
</Project>"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "CMakeCache.txt").write_bytes(b"CMAKE_CACHE_MAJOR_VERSION:INTERNAL=4\r\n"
                b"CMAKE_CACHE_MINOR_VERSION:INTERNAL=1\r\nCMAKE_CACHE_PATCH_VERSION:INTERNAL=3\r\n")
            cmake_root = root / "CMakeFiles/4.1.3"
            cmake_root.mkdir(parents=True)
            (cmake_root / "CMakeCXXCompiler.cmake").write_bytes(b'set(CMAKE_CXX_COMPILER_ID "MSVC")\n'
                b'set(CMAKE_CXX_COMPILER_VERSION "19.44.35207.0")\n')
            for name in ("FlowBridge", "FlowBridgeNativeSmoke"):
                (root / (name + ".vcxproj")).write_text(project)
            result = audit.generated_msvc_settings(root)
            self.assertEqual(result["msvc_cxx_compiler_version"], "19.44.35207.0")
            self.assertEqual(result["targets"]["FlowBridge"]["runtime_library"], "MultiThreaded")
            self.assertFalse(result["static_linker_members_verified"])
            (root / "FlowBridge.vcxproj").write_text(project.replace("MultiThreaded", "MultiThreadedDLL"))
            with self.assertRaisesRegex(audit.Rejected, "msvc_release_static_runtime"):
                audit.generated_msvc_settings(root)


if __name__ == "__main__":
    unittest.main()
