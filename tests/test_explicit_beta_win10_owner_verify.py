"""Synthetic positive and adversarial inputs for independent A3 review."""
from __future__ import annotations

import copy
import json
import pathlib
import struct
import sys
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import explicit_beta_win10_owner_verify as verify  # noqa: E402


def bmp(marker: int) -> bytes:
    width, height = 128, 112
    stride = (width * 3 + 3) & ~3
    pixels = bytes([marker]) * (stride * height)
    length = 54 + len(pixels)
    return (
        b"BM" + struct.pack("<IHHI", length, 0, 0, 54) +
        struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0,
                    len(pixels), 0, 0, 0, 0) + pixels
    )


def fixture() -> tuple[dict, dict[str, bytes]]:
    images = {f"installed-beta-ui-compact-{name}.bmp": bmp(i + 1)
              for i, name in enumerate(verify.PAGES)}
    report = {
        "schema": "flowbridge-explicit-beta-native-powershell-a3-v1",
        "source_sha": verify.SOURCE,
        "candidate_run_id": verify.RUN,
        "candidate_version": verify.VERSION,
        "status": "OWNER_NATIVE_AUTOMATED_CHECKS_PASS",
        "owner_native": True,
        "host_identity_basis": "operator_supplied_not_attested",
        "initial_preflight": "PINNED_BYTES_PASS",
        "checks": {name: "PASS" for name in verify.PHASES},
        "screenshots": [{"name": n, "sha256": verify.sha(data)}
                        for n, data in sorted(images.items())],
        **{name: False for name in verify.FALSE_FLAGS},
    }
    return report, images


def raw(report: dict) -> bytes:
    return json.dumps(report).encode("utf-8")


class TestA3IndependentReview(unittest.TestCase):
    def test_five_bmp_six_phases_structure_only(self) -> None:
        report, images = fixture()
        result = verify.audit(raw(report), images)
        self.assertEqual(result["status"], "EVIDENCE_STRUCTURE_PASS_MANUAL_REVIEW_OPEN")
        self.assertEqual(result["screenshots_verified"], 5)
        for key in ("host_independently_attested", "manual_gui_keyboard_ssh_checked",
                    "a3_full_acceptance", "wfp_g2_accepted", "release_accepted"):
            self.assertIs(result[key], False)

    def test_folder_and_nested_zip_identical(self) -> None:
        report, images = fixture()
        with tempfile.TemporaryDirectory() as t:
            root = pathlib.Path(t)
            (root / "native-acceptance.json").write_bytes(raw(report))
            for name, data in images.items():
                (root / name).write_bytes(data)
            local = verify.from_dir(root)
            self.assertEqual(verify.audit(*local)["screenshots_verified"], 5)
            archive = root / "handoff.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("a3-nopython-report/native-acceptance.json", raw(report))
                for name, data in images.items():
                    z.writestr("a3-nopython-report/" + name, data)
            zipped = verify.from_zip(archive)
            self.assertEqual(verify.audit(*zipped)["screenshots_verified"], 5)

    def test_refuse_forged_host_and_release_claims(self) -> None:
        report, images = fixture()
        variants = (
            ("owner_native", False),
            ("host_identity_basis", "verified_by_os"),
            ("status", "CI_AUTOMATED_CHECKS_PASS"),
            ("initial_preflight", "NOT_RUN"),
            ("source_sha", "wrong"),
            ("candidate_run_id", "other"),
            ("cleanup_required", True),
            ("a3_full_acceptance", True),
            ("release_accepted", True),
            ("wfp_g2_accepted", True),
            ("system_dns_changed", True),
            ("python_required", True),
        )
        for field, value in variants:
            case = copy.deepcopy(report)
            case[field] = value
            with self.subTest(field=field), self.assertRaises(verify.Rejected):
                verify.audit(raw(case), images)

    def test_refuse_partial_phase_or_missing_screenshot(self) -> None:
        report, images = fixture()
        report["checks"]["uninstall"] = "NOT_RUN"
        with self.assertRaises(verify.Rejected):
            verify.audit(raw(report), images)
        report, images = fixture()
        report["screenshots"].pop()
        with self.assertRaises(verify.Rejected):
            verify.audit(raw(report), images)
        report, images = fixture()
        images.pop(sorted(images)[0])
        with self.assertRaises(verify.Rejected):
            verify.audit(raw(report), images)

    def test_refuse_falsified_bmp_hash_bad_header_and_duplicate_image(self) -> None:
        report, images = fixture()
        name = sorted(images)[0]
        changed = dict(images)
        changed[name] = changed[name][:-1] + b"z"
        with self.assertRaises(verify.Rejected):
            verify.audit(raw(report), changed)
        changed = dict(images)
        changed[name] = b"PNG" + changed[name][3:]
        with self.assertRaises(verify.Rejected):
            verify.audit(raw(report), changed)
        report, images = fixture()
        names = sorted(images)
        images[names[1]] = images[names[0]]
        for item in report["screenshots"]:
            if item["name"] == names[1]:
                item["sha256"] = verify.sha(images[names[1]])
        with self.assertRaises(verify.Rejected):
            verify.audit(raw(report), images)

    def test_refuse_zip_traversal_or_resource_exhaustion(self) -> None:
        report, images = fixture()
        with tempfile.TemporaryDirectory() as t:
            path = pathlib.Path(t) / "evil.zip"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("../evil.txt", "bad")
                z.writestr("native-acceptance.json", raw(report))
                for name, data in images.items():
                    z.writestr(name, data)
            with self.assertRaises(verify.Rejected):
                verify.from_zip(path)
            with zipfile.ZipFile(path, "w") as z:
                for i in range(513):
                    z.writestr(f"junk{i}", b"x")
            with self.assertRaises(verify.Rejected):
                verify.from_zip(path)


if __name__ == "__main__":
    unittest.main()
