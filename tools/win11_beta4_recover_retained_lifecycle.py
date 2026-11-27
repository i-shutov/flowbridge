#!/usr/bin/env python3
"""Recover only the owned residue of Win11 headless lifecycle run 46041604814."""
from __future__ import annotations

import ctypes
import hashlib
import json
import ntpath
from pathlib import Path
import subprocess
import sys

import win11_beta4_headless_lifecycle as qa
import win11_explicit_beta_preflight as preflight

WORK_ID = "qa-beta4-74021cde30d34727bcce54f0d6a85283"
INSTALL = "FlowBridge Тест QA With Spaces"
DEVICE = 10108441072652092086
DIRECTORIES = {"": 281474977745904, INSTALL: 281474977745909,
               "tmp": 281474977745905, "tmp/~nsu1.tmp": 281474977745938}
FILES = {
    f"{INSTALL}/{qa.PRESERVE}": (281474977745934, 43,
                              "90650db13aa546cb7d3b37898e3787bd7d70beb717343f2e6240e949f7e1c2fc"),
    "tmp/~nsu1.tmp/un.exe": (281474977745939, 64057,
                           "86ef3f88a4ac08a46d30187da0ac2e6386b34b77e1a23df44889992dca53a3b4"),
}
CANDIDATE_RUN = "run-beta4-46040903481-1"
PINS = {
    "source": "c8881dada43e3183a0340dc823105bdcdac71171",
    "tree": "ce336e83bb724a65bf512e79e286c97fb0cb3190",
    "installer": "e0e4491cd97b30aa52b52ce89a7a8396a2fc11902bec3e70bed8ebfd722450b0",
    "manifest": "3542633d089aff80e379f30db8be6f301edae462f38f70ea07c5b8ba76011703",
    "harness": "46cd8970cf669e0be3493998aeec6ba30ecb464dd399d0c3cdd972444e193a32",
    "tool": "faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c",
}
DESKTOP_FIXTURE = b'{"version":1,"managed_ssh":false,"ssh_workers":1}\n'
require = preflight.require


def verify_work(work):
    expected = (DIRECTORIES.keys() - {""}) | FILES.keys()
    expected_normalized = {ntpath.normcase(name) for name in expected}
    observed = {}
    for name in qa.contents(work):
        normalized = ntpath.normcase(name)
        require(normalized not in observed, "work_inventory_case_collision")
        observed[normalized] = name
    require(len(observed) == len(expected) and observed.keys() == expected_normalized,
            "work_inventory_changed")

    # The observer normalized known NSIS names. Resolve their actual spelling
    # before requiring the exact observed file IDs and bytes.
    directories = {work / observed[ntpath.normcase(name)] if name else work: (DEVICE, identity)
                   for name, identity in DIRECTORIES.items()}
    files = {work / observed[ntpath.normcase(name)]: (DEVICE, identity, size, sha)
             for name, (identity, size, sha) in FILES.items()}
    for path, expected in directories.items():
        require(qa.directory_id(path) == expected, "observed_work_directory_identity_changed")
    for path in files:
        qa.verify_recorded_file(path, files)
    return directories, files


def verify_profile(profile, manifest):
    require(qa.contents(profile) == {"profile.json", "desktop-settings.json"},
            "test_profile_inventory_changed")
    directories = {profile: qa.directory_id(profile)}
    profile_pin = manifest[qa.REPAIR]
    expected = {"profile.json": (profile_pin["bytes"], profile_pin["sha256"]),
                "desktop-settings.json": (len(DESKTOP_FIXTURE), hashlib.sha256(DESKTOP_FIXTURE).hexdigest())}
    files = {}
    for name, (size, digest) in expected.items():
        file = profile / name
        record = qa.file_snapshot(file, size)
        require(record[3] == digest, "synthetic_profile_content_changed")
        files[file] = record
    return directories, files


def verify_registry_residue():
    residue = qa.registry_snapshot()
    require(all(entry == ((0, {}) if key == qa.SETTINGS else None)
                for (key, _), entry in residue.items()), "observed_registry_residue_changed")
    return residue


def remove_empty_beta_settings():
    import winreg

    for view in qa.registry_views():
        detected = qa.registry_key(qa.SETTINGS, view)
        if detected is not None:  # Both registry views may refer to the same key.
            require(detected == (0, {}), "nonempty_beta_settings_before_recovery")
            winreg.DeleteKeyEx(winreg.HKEY_CURRENT_USER, qa.SETTINGS, view, 0)


def verify_shared_baseline(work, kernel):
    state = preflight.installed_state(kernel)
    require(state["flowbridge_process_count"] == 0 and qa.private_work_process_count(work) == 0,
            "recovery_process_still_running")
    stable = state["stable"]
    require(all(value == "absent" for name, value in stable.items() if name != "registry")
            and all(qa.registry_key(key, view) is None for view in qa.registry_views() for key in
                    (r"Software\FlowBridge", r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridge")),
            "stable_baseline_changed")
    require(state["beta"]["shortcuts_directory"] == "absent"
            and state["beta"]["default_install_directory"] == "absent", "unexpected_beta_path_present")


def recover(kernel, report):
    base = Path(preflight.PRIVATE)
    work = base / WORK_ID
    candidate_root = base / CANDIDATE_RUN / "candidate"
    local, _ = preflight.known_folders()
    profile = local / "FlowBridgeExplicitBeta"
    candidate = preflight.probe_candidate(candidate_root, PINS)
    payload = candidate["manifest_payload"]
    report["runner_result_sha256"] = qa.verify_runner_result(candidate_root, PINS, payload)

    # Verify all expected state before deleting anything. Recheck shared state
    # immediately before the removal sequence, under the lab's serialized QA.
    verify_shared_baseline(work, kernel)
    work_dirs, work_files = verify_work(work)
    profile_dirs, profile_files = verify_profile(profile, payload)
    registry = verify_registry_residue()
    verify_shared_baseline(work, kernel)
    require(qa.registry_snapshot() == registry, "registry_changed_before_recovery")
    report["observed_work_and_synthetic_profile_verified"] = True

    report["mutation_started"] = True
    qa.remove_owned_tree(work, work_dirs, work_files)
    report["observed_work_removed"] = True
    qa.remove_owned_tree(profile, profile_dirs, profile_files)
    report["synthetic_profile_removed"] = True
    require(qa.registry_snapshot() == registry, "registry_changed_before_recovery")
    remove_empty_beta_settings()
    report["empty_beta_settings_removed"] = True
    require(preflight.path_status(work) == "absent", "retained_work_remains")
    qa.require_clean(kernel)
    preflight.probe_candidate(candidate_root, PINS)
    report["clean_baseline_verified"] = True
    report["candidate_pins_unchanged"] = True


def main():
    report = {"schema": "flowbridge-win11-beta4-retained-cleanup-v1",
              "work_id": WORK_ID, "failed_run": 46041604814, "observation_run": 46042401435,
              "mutation_started": False, "native_lifecycle_accepted_by_recovery": False,
              "nsis_machine_pending_rename_queue": {"inspection": "NOT_INSPECTED", "qa_direct_write": False}}
    try:
        require(sys.platform == "win32", "wrong_execution_platform")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        report["host"] = preflight.windows_host(kernel)
        require(preflight.current_session(kernel) == 0 and report["host"]["token_elevated"],
                "requires_elevated_lab_session_zero")
        recover(kernel, report)
        report["status"] = "OWNED_RECOVERY_COMPLETE"
        code = 0
    except (preflight.Blocked, OSError, subprocess.SubprocessError) as error:
        report["status"] = "RECOVERY_BLOCKED"
        report["failure"] = str(error) if isinstance(error, preflight.Blocked) else type(error).__name__
        code = 1
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
