#!/usr/bin/env python3
"""Read-only independent structure/hash audit of owner Win10 A3 evidence.

This does NOT attest the host, interact with Windows, inspect GUI semantics,
run binaries, or approve the beta / WFP G2. Input is untrusted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import sys
import zipfile

SOURCE = "f5ecd48d8f81c594f755a55e7969b57d20903020"
RUN = "43407093536"
VERSION = "0.3.0-beta.1"
PAGES = ("dashboard", "ssh", "proxy", "apps", "advanced")
NAMES = {f"installed-beta-ui-compact-{p}.bmp" for p in PAGES}
PHASES = ("install", "payload", "launch", "upgrade", "uninstall", "stable_preserved")
FALSE_FLAGS = (
    "a3_full_acceptance", "release_accepted", "wfp_g2_accepted",
    "transparent_interception_accepted", "driver_loaded",
    "system_dns_changed", "python_required", "cleanup_required",
)


class Rejected(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Rejected(code)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bmp_ok(data: bytes) -> bool:
    if len(data) < 1554 or data[:2] != b"BM":
        return False
    try:
        size = struct.unpack_from("<I", data, 2)[0]
        offset = struct.unpack_from("<I", data, 10)[0]
        dib = struct.unpack_from("<I", data, 14)[0]
        width, height = struct.unpack_from("<ii", data, 18)
        planes, bits = struct.unpack_from("<HH", data, 26)
        return (
            54 <= size <= len(data) and
            54 <= offset < len(data) and dib >= 40 and
            100 <= width <= 10000 and 100 <= abs(height) <= 10000 and
            planes == 1 and bits in (24, 32)
        )
    except struct.error:
        return False


def audit(report_bytes: bytes, images: dict[str, bytes]) -> dict:
    require(len(report_bytes) <= 512 * 1024, "REPORT_TOO_LARGE")
    try:
        report = json.loads(report_bytes.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as ex:
        raise Rejected("INVALID_JSON") from ex
    require(isinstance(report, dict), "REPORT_NOT_OBJECT")
    require(report.get("schema") == "flowbridge-explicit-beta-native-powershell-a3-v1", "SCHEMA_MISMATCH")
    require(report.get("source_sha") == SOURCE and
            str(report.get("candidate_run_id")) == RUN and
            report.get("candidate_version") == VERSION, "FROZEN_SOURCE_MISMATCH")
    require(report.get("status") == "OWNER_NATIVE_AUTOMATED_CHECKS_PASS", "OWNER_AUTOMATED_NOT_PASS")
    require(report.get("owner_native") is True and
            report.get("host_identity_basis") == "operator_supplied_not_attested",
            "OWNER_CLAIM_OR_ATTESTATION_INVALID")
    require(report.get("initial_preflight") == "PINNED_BYTES_PASS", "PINNED_BYTES_NOT_PASS")
    checks = report.get("checks")
    require(isinstance(checks, dict) and
            all(checks.get(p) == "PASS" for p in PHASES), "SIX_PHASES_INCOMPLETE")
    for flag in FALSE_FLAGS:
        require(report.get(flag) is False, "UNSUPPORTED_FLAG_" + flag.upper())

    shots = report.get("screenshots")
    require(isinstance(shots, list) and len(shots) == len(PAGES), "SHOT_COUNT_NOT_FIVE")
    observed: set[str] = set()
    digests: set[str] = set()
    sizes: dict[str, int] = {}
    for item in shots:
        require(isinstance(item, dict), "SHOT_ENTRY_INVALID")
        name, expected = item.get("name"), item.get("sha256")
        require(isinstance(name, str) and name in NAMES and name not in observed,
                "SHOT_FILENAME_INVALID_OR_DUPLICATE")
        require(isinstance(expected, str) and len(expected) == 64 and
                expected == expected.lower(), "SHOT_DIGEST_INVALID")
        require(name in images, "SHOT_BYTES_MISSING")
        data = images[name]
        require(bmp_ok(data), "SHOT_BMP_INVALID")
        actual = sha(data)
        require(actual == expected, "SHOT_SHA256_MISMATCH")
        require(actual not in digests, "SHOT_CONTENT_DUPLICATE")
        observed.add(name)
        digests.add(actual)
        sizes[name] = len(data)
    require(observed == NAMES, "SHOT_SET_INCOMPLETE")
    return {
        "schema": "flowbridge-a3-independent-evidence-review-v1",
        "status": "EVIDENCE_STRUCTURE_PASS_MANUAL_REVIEW_OPEN",
        "source_sha": SOURCE,
        "candidate_run_id": RUN,
        "checks": {p: "PASS" for p in PHASES},
        "screenshots_verified": len(NAMES),
        "screenshot_sizes_bytes": dict(sorted(sizes.items())),
        "owner_native_claimed": True,
        "host_independently_attested": False,
        "manual_gui_keyboard_ssh_checked": False,
        "a3_full_acceptance": False,
        "wfp_g2_accepted": False,
        "release_accepted": False,
    }


def from_dir(root: pathlib.Path) -> tuple[bytes, dict[str, bytes]]:
    require(root.is_dir() and not root.is_symlink(), "EVIDENCE_DIR_MISSING")
    report_path = root / "native-acceptance.json"
    require(report_path.is_file() and not report_path.is_symlink(), "REPORT_MISSING_OR_LINK")
    report = report_path.read_bytes()
    images: dict[str, bytes] = {}
    for name in NAMES:
        path = root / name
        require(path.is_file() and not path.is_symlink(), "SHOT_MISSING_OR_LINK")
        require(path.stat().st_size <= 30 * 1024 * 1024, "SHOT_TOO_LARGE")
        images[name] = path.read_bytes()
    return report, images


def from_zip(path: pathlib.Path) -> tuple[bytes, dict[str, bytes]]:
    require(path.is_file() and path.stat().st_size <= 80 * 1024 * 1024,
            "ZIP_MISSING_OR_TOO_LARGE")
    try:
        with zipfile.ZipFile(path) as z:
            entries = z.infolist()
            require(len(entries) <= 512 and
                    sum(e.file_size for e in entries) <= 120 * 1024 * 1024,
                    "ZIP_RESOURCE_LIMIT")
            names = [e.filename.replace("\\", "/") for e in entries if not e.is_dir()]
            require(len(names) == len(set(names)), "AMBIGUOUS_ZIP_ENTRIES")
            for e in entries:
                p = pathlib.PurePosixPath(e.filename.replace("\\", "/"))
                require(not p.is_absolute() and ".." not in p.parts and
                        ":" not in e.filename and
                        (e.external_attr >> 16) & 0o170000 != 0o120000,
                        "UNSAFE_ZIP_ENTRY")
            matches = [n for n in names if pathlib.PurePosixPath(n).name == "native-acceptance.json"]
            require(len(matches) == 1, "REPORT_MISSING_OR_AMBIGUOUS")
            prefix = matches[0][:-len("native-acceptance.json")]
            require(all(prefix + n in names for n in NAMES), "SHOT_BYTES_MISSING")
            report = z.read(matches[0])
            images = {n: z.read(prefix + n) for n in NAMES}
            return report, images
    except (zipfile.BadZipFile, EOFError) as ex:
        raise Rejected("INVALID_ZIP") from ex


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=pathlib.Path, help="A3 report folder or ZIP of that folder")
    parser.add_argument("--output", type=pathlib.Path, help="Optional independent verdict JSON")
    args = parser.parse_args()
    try:
        report, images = from_dir(args.evidence) if args.evidence.is_dir() else from_zip(args.evidence)
        verdict = audit(report, images)
        code = 0
    except (Rejected, OSError, ValueError, KeyError) as ex:
        verdict = {
            "schema": "flowbridge-a3-independent-evidence-review-v1",
            "status": "REJECTED",
            "error_code": str(ex) if isinstance(ex, Rejected) else "EVIDENCE_READ_ERROR",
            "a3_full_acceptance": False,
            "wfp_g2_accepted": False,
            "release_accepted": False,
        }
        code = 1
    result = json.dumps(verdict, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    print(result, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
