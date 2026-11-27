"""Emit reviewable provenance for the hosted-only expanded-descriptor lab."""

import argparse
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from windows_ssh_probe_core import RAW_CAPACITY, RECOVERY_CONNECTIONS, raw_capacity_verified


OPENSSH_SOURCE = "274893f8d1fe86c4d128b514c3af4bc10cdc0c99"
VCPKG_SOURCE = "99541cc939bf01ae3c42f928266d648f5acb88fd"
VCPKG_BASELINE = "a345bbdc68cdfda65603e24413b21afb28f110fb"
VCPKG_MANIFEST = "contrib/win32/openssh/vcpkg.json"
REGISTRY_OVERRIDES = {"zlib": "1.3.2", "libcbor": "0.14.0"}
HEADER = "contrib/win32/win32compat/inc/sys/select.h"
HEADER_ORIGINAL = "77b2fbe3f7c0992a8d62cf6ba46013d60b4365c8e4d34a28d3531f30867fb0df"
HEADER_EXPERIMENTAL = "e9b21fbec79a4eaad87c1b4de5db7384e4df6513e069d804c47b635c96fa41a1"
STOCK_DESCRIPTORS = 256
LAB_DESCRIPTORS = 1024
REQUIRED_BINARIES = {"ssh.exe", "sshd.exe", "sshd-auth.exe", "sshd-session.exe",
                     "ssh-keygen.exe", "libcrypto.dll"}
RESOURCE_CATEGORIES = {"too_many_open_files", "no_buffer_space", "allocation_failure",
                       "postauth_notify_pipe_file_limit"}


class LabFailure(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise LabFailure(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(tree, *args):
    return subprocess.check_output(["git", "-C", str(tree), *args], timeout=30)


def expanded_header(original):
    require(digest(original) == HEADER_ORIGINAL, "upstream_select_header_mismatch")
    old = f"#define MAX_FDS {STOCK_DESCRIPTORS}".encode()
    new = f"#define MAX_FDS {LAB_DESCRIPTORS}".encode()
    require(original.count(old) == 1, "descriptor_define_not_unique")
    result = original.replace(old, new, 1)
    require(digest(result) == HEADER_EXPERIMENTAL, "experimental_select_header_mismatch")
    return result


def verify_checkouts(source, dependencies):
    for tree, pin in ((source, OPENSSH_SOURCE), (dependencies, VCPKG_SOURCE)):
        require(git(tree, "rev-parse", "HEAD").decode().strip() == pin, "upstream_commit_mismatch")
        require(not git(tree, "diff", "--cached", "--name-only"), "upstream_index_dirty")


def verify_source_change(source, dependencies):
    verify_checkouts(source, dependencies)
    require(git(source, "diff", "--name-only").decode().splitlines() == [HEADER],
            "lab_must_modify_only_select_header")
    require(not git(dependencies, "diff", "--name-only"), "vcpkg_source_modified")
    require(digest((source / HEADER).read_bytes()) == HEADER_EXPERIMENTAL,
            "experimental_select_header_mismatch")


def verify_registry(source, dependencies):
    # The upstream 2024 baseline predates two explicit manifest overrides.
    # Keep that baseline and use a pinned registry history containing the requested versions.
    manifest = read_report(source / VCPKG_MANIFEST)
    require(manifest.get("builtin-baseline") == VCPKG_BASELINE, "upstream_vcpkg_baseline_changed")
    git(dependencies, "merge-base", "--is-ancestor", VCPKG_BASELINE, "HEAD")
    for name, version in REGISTRY_OVERRIDES.items():
        require({"name": name, "version": version} in manifest.get("overrides", []),
                "upstream_manifest_override_changed")
        history = read_report(dependencies / "versions" / f"{name[0]}-" / f"{name}.json").get("versions", [])
        require(any(port.get("version") == version and port.get("port-version") == 0 for port in history),
                "pinned_vcpkg_registry_missing_override")


def prepare(source, dependencies):
    verify_checkouts(source, dependencies)
    require(all(not git(tree, "status", "--porcelain", "--untracked-files=all")
                for tree in (source, dependencies)), "upstream_checkout_dirty")
    verify_registry(source, dependencies)
    path = source / HEADER
    path.write_bytes(expanded_header(path.read_bytes()))
    verify_source_change(source, dependencies)


def runtime_hashes(directory):
    files = {}
    for member in directory.iterdir():
        info = member.lstat()
        require(stat.S_ISREG(info.st_mode) and not (getattr(info, "st_file_attributes", 0) & 0x400)
                and member.suffix.lower() in {".exe", ".dll"}, "unexpected_lab_binary")
        name = member.name.lower()
        require(name not in files, "duplicate_lab_binary")
        data = member.read_bytes()
        offset = int.from_bytes(data[60:64], "little")
        require(data[:2] == b"MZ" and offset >= 64 and data[offset:offset + 6] == b"PE\0\0\x64\x86",
                "expected_windows_x64_pe")
        files[name] = digest(data)
    require(REQUIRED_BINARIES <= files.keys(), "incomplete_lab_runtime")
    require({name for name in files if name.endswith(".exe")}
            == {name for name in REQUIRED_BINARIES if name.endswith(".exe")}, "unexpected_lab_executable")
    return files


def build_record(source, dependencies, runtime):
    verify_source_change(source, dependencies)
    return {
        "status": "COMPILED_HOSTED_EXPERIMENT",
        "openssh_source_sha": OPENSSH_SOURCE,
        "vcpkg_source_sha": VCPKG_SOURCE,
        "vcpkg_builtin_baseline": VCPKG_BASELINE,
        "vcpkg_registry_overrides": REGISTRY_OVERRIDES,
        "single_tracked_change": HEADER,
        "original_header_sha256": HEADER_ORIGINAL,
        "experimental_header_sha256": HEADER_EXPERIMENTAL,
        "stock_descriptors": STOCK_DESCRIPTORS, "experimental_descriptors": LAB_DESCRIPTORS,
        "runtime_sha256": runtime_hashes(runtime),
    }


def nonnegative(value):
    return value if type(value) is int and value >= 0 else None


def resource_counts(report, key):
    values = report.get(key)
    if not isinstance(values, dict):
        return {}
    return {name: value for name, value in values.items()
            if name in RESOURCE_CATEGORIES and nonnegative(value) is not None}


def summary(evidence, wrapper, binary_hashes, process_exit):
    same_binaries = (evidence.get("actual_ssh_executable_sha256") == binary_hashes["ssh.exe"]
                     and wrapper.get("ssh_sha256") == binary_hashes["ssh.exe"]
                     and wrapper.get("sshd_sha256") == binary_hashes["sshd.exe"])
    raw_loopback = (wrapper.get("scenario") == "raw"
                    and wrapper.get("hosted_windows_runner") is True
                    and wrapper.get("network_test_destinations_loopback_only") is True
                    and wrapper.get("managed_acceptance_proved") is False
                    and wrapper.get("ffi_sha256") is None
                    and wrapper.get("cli_sha256") is None
                    and evidence.get("windows_openssh_tested") is True
                    and evidence.get("external_network") is False)
    verified = (process_exit == 0 and same_binaries and raw_loopback
                and wrapper.get("passed") is True
                and wrapper.get("raw_backend_512_stability_proved") is True
                and raw_capacity_verified(evidence))
    ran_recovery = evidence.get("capacity_baseline_verified") is True
    verified_recovery = evidence.get("resource_recovery_verified") is True
    return {
        "schema": "flowbridge-hosted-openssh-raw512-lab-v1",
        "status": "LAB_STRICT_512_PASS" if verified else "LAB_STRICT_512_NOT_MET",
        "raw_minimum_held": RAW_CAPACITY,
        "raw_recovery_required": RECOVERY_CONNECTIONS,
        "actual_connection_attempts": nonnegative(evidence.get("actual_connection_attempts")),
        "peak_held": nonnegative(evidence.get("peak_held")),
        "recovery_successes": nonnegative(evidence.get("recovery_successes")),
        "hold_integrity_verified": ran_recovery,
        "recovery_status": ("VERIFIED" if verified_recovery else "NOT_VERIFIED")
                           if ran_recovery else "NOT_REACHED",
        "client_resource_error_counts": resource_counts(evidence, "resource_error_counts"),
        "fixture_server_resource_error_counts": resource_counts(wrapper, "fixture_server_resource_error_counts"),
        "raw_process_exit": process_exit,
        "lab_binary_pins_match": same_binaries,
        "hosted_unsigned_experiment": True,
        "production_raw512_accepted": False,
        "production_adoption_approved": False,
        "frozen_beta3_changed": False,
    }


def read_report(path):
    if not path.is_file():
        return {}
    with path.open("rb") as stream:
        data = stream.read(65537)
    require(len(data) <= 65536, "lab_report_too_large")
    report = json.loads(data)
    require(isinstance(report, dict), "invalid_lab_report")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "built", "result"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--vcpkg", type=Path, required=True)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--reports", type=Path)
    parser.add_argument("--probe-exit", type=int)
    args = parser.parse_args()
    if args.phase == "prepare":
        prepare(args.source, args.vcpkg)
        return 0

    require(args.runtime is not None and args.receipt is not None, "expected_runtime_and_receipt")
    record = build_record(args.source, args.vcpkg, args.runtime)
    if args.phase == "built":
        with args.receipt.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True)
        print("FLOWBRIDGE_RAW512_LAB_BUILD " + json.dumps(record, sort_keys=True))
        return 0

    require(read_report(args.receipt) == record, "compiled_runtime_changed_since_build")
    require(args.reports is not None and args.probe_exit is not None, "expected_probe_evidence")
    result = summary(read_report(args.reports / "bare-backend-capacity.json"),
                     read_report(args.reports / "summary.json"), record["runtime_sha256"], args.probe_exit)
    print("FLOWBRIDGE_RAW512_LAB_RESULT " + json.dumps(result, sort_keys=True))
    return int(result["status"] != "LAB_STRICT_512_PASS")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LabFailure as error:
        print("FLOWBRIDGE_RAW512_LAB_EVIDENCE_BLOCKED=" + str(error))
        sys.exit(1)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("FLOWBRIDGE_RAW512_LAB_EVIDENCE_BLOCKED=invalid_or_unavailable_local_evidence")
        sys.exit(1)
