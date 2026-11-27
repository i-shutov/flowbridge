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


if __name__ == "__main__":
    unittest.main()
