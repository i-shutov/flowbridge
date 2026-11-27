#!/usr/bin/env python3
"""Exact beta.4 installer lifecycle on the clean Win11 Session 0 lab."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import win11_explicit_beta_preflight as preflight

SETTINGS = r"Software\FlowBridgeExplicitBeta"
UNINSTALL = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridgeExplicitBeta"
SHORTCUTS = {"FlowBridge.lnk": "FlowBridge.exe", "Help.lnk": "README.txt",
             "Uninstall.lnk": "Uninstall.exe"}
PRESERVE = "qa-preserve-user-file.txt"
REPAIR = "examples/direct.json"
INSTALL_SUBDIRS = ("examples", "licenses", "resources")
CHECKS = ("clean_baseline", "install", "payload", "cli", "reinstall",
          "uninstall", "profile_preserved", "stable_preserved", "cleanup")
require = preflight.require


def verify_runner_result(root, pins, payload):
    evidence = root.parent / "runner-result.json"
    require(preflight.path_status(evidence) == "regular_file", "runner_result_missing_or_unsafe")
    with evidence.open("rb") as stream:
        encoded = stream.read(65537)
    require(0 < len(encoded) <= 65536, "runner_result_size_invalid")
    try:
        result = json.loads(encoded)
    except (ValueError, UnicodeError):
        raise preflight.Blocked("runner_result_json_invalid") from None
    expected = {
        "schema": "flowbridge-private-beta4-runner-v1",
        "candidate": preflight.VERSION,
        "phase": "PACKAGE_EVIDENCE",
        "status": "PRIVATE_LOCAL_INSTALLER_BUILT_QA_NOT_ACCEPTED",
        "installer_built": True,
        "installer_installed": False,
        "driver_included": False,
        "staged_payload_allowlist_verified": True,
        "win11_product_accepted": False,
        "new_private_git_commit": pins["source"],
        "new_private_git_tree": pins["tree"],
        "installer_sha256": pins["installer"],
        "package_manifest_sha256": pins["manifest"],
        "qa_harness_sha256": pins["harness"],
        "acceptance_tool_sha256": pins["tool"],
        "gui_sha256": payload["FlowBridge.exe"]["sha256"],
        "cli_sha256": payload["flowbridge-cli.exe"]["sha256"],
        "ffi_sha256": payload["flowbridge_ffi.dll"]["sha256"],
    }
    require(isinstance(result, dict) and all(type(result.get(key)) is type(value) and result[key] == value
                                            for key, value in expected.items()), "runner_result_binding_failed")
    return hashlib.sha256(encoded).hexdigest()


def registry_key(key, view):
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_READ | view) as handle:
            subkeys, count, _ = winreg.QueryInfoKey(handle)
            return subkeys, {name: value for name, value, _ in
                             (winreg.EnumValue(handle, index) for index in range(count))}
    except FileNotFoundError:
        return None


def registry_views():
    import winreg

    return winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY


def require_clean(kernel):
    state = preflight.installed_state(kernel)
    require(preflight.isolation_status(state) == "ISOLATION_BASELINE_AVAILABLE",
            "existing_beta_or_product_process")
    require(all(value == "absent" for name, value in state["stable"].items() if name != "registry"),
            "existing_stable_path")
    for key in (SETTINGS, UNINSTALL, r"Software\FlowBridge",
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridge"):
        require(all(registry_key(key, view) is None for view in registry_views()),
                "existing_flowbridge_registry_key")
    return state


def private_directory(path, kernel):
    """Create a protected directory atomically with SYSTEM and Administrators ACL."""

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("size", w.DWORD), ("security_descriptor", ctypes.c_void_p), ("inherit", w.BOOL)]

    security = ctypes.WinDLL("advapi32", use_last_error=True)
    descriptor = ctypes.c_void_p()
    convert = preflight.api(security, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                            w.BOOL, w.LPCWSTR, w.DWORD, ctypes.POINTER(ctypes.c_void_p),
                            ctypes.POINTER(w.DWORD))
    require(convert("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, ctypes.byref(descriptor), None),
            "private_acl_creation_failed")
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        create = preflight.api(kernel, "CreateDirectoryW", w.BOOL, w.LPCWSTR,
                               ctypes.POINTER(SecurityAttributes))
        require(create(str(path), ctypes.byref(attributes)), "private_directory_creation_failed")
    finally:
        preflight.api(kernel, "LocalFree", ctypes.c_void_p, ctypes.c_void_p)(descriptor)


def directory_id(path):
    require(preflight.path_status(path) == "directory", "unexpected_directory_type")
    value = path.stat()
    return value.st_dev, value.st_ino


def file_snapshot(path, expected_size=None):
    require(preflight.path_status(path) == "regular_file", "unexpected_file_type")
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        require(expected_size is None or info.st_size == expected_size, "owned_file_size_changed")
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    return info.st_dev, info.st_ino, info.st_size, sha


def write_fixture(path, data, recorded):
    with path.open("xb") as stream:
        info = os.fstat(stream.fileno())
        recorded[path] = (info.st_dev, info.st_ino, len(data), hashlib.sha256(data).hexdigest())
        stream.write(data)


def verify_recorded_file(path, recorded):
    require(path in recorded and file_snapshot(path, recorded[path][2]) == recorded[path],
            "file_content_or_identity_changed")


def remove_owned_tree(root, directories, files):
    """Validate all surviving members before removing any part of this tree."""
    if preflight.path_status(root) == "absent":
        return
    require(root in directories and directory_id(root) == directories[root],
            "unproven_cleanup_directory")
    descendants = [root / relative for relative in contents(root)]
    for path in descendants:
        if path in directories:
            require(directory_id(path) == directories[path], "cleanup_directory_identity_changed")
        else:
            verify_recorded_file(path, files)
    for path in sorted(descendants, key=lambda item: len(item.parts), reverse=True):
        if path in directories:
            path.rmdir()
        else:
            path.unlink()
    root.rmdir()


def contents(root):
    """Enumerate a small, regular tree without descending through reparse points."""
    paths = set()
    queue = [root]
    while queue:
        path = queue.pop()
        kind = preflight.path_status(path)
        require(kind in ("directory", "regular_file"), "unsafe_tree_entry")
        if path != root:
            paths.add(path.relative_to(root).as_posix())
            require(len(paths) <= 128, "unexpected_tree_cardinality")
        if kind == "directory":
            queue.extend(path.iterdir())
    return paths


def wait_for(predicate, reason, timeout=35):
    deadline = time.monotonic() + timeout
    while not predicate():
        require(time.monotonic() < deadline, reason)
        time.sleep(0.2)


def empty(directory):
    return preflight.path_status(directory) == "directory" and next(directory.iterdir(), None) is None


def known_registry(install):
    exe = install / "Uninstall.exe"
    uninstall = {"DisplayName": "FlowBridge", "DisplayVersion": preflight.VERSION,
                 "Publisher": "FlowBridge contributors", "InstallLocation": str(install),
                 "DisplayIcon": str(install / "FlowBridge.exe"), "UninstallString": f'"{exe}"',
                 "QuietUninstallString": f'"{exe}" /S', "NoModify": 1, "NoRepair": 1}
    return {"InstallDir": str(install)}, uninstall


def owned_registry(key, entry, install):
    if entry is None:
        return True
    settings, uninstall = known_registry(install)
    subkeys, values = entry
    anchor = "InstallDir" if key == SETTINGS else "InstallLocation"
    if subkeys or values.get(anchor) != str(install):
        return False
    for name, actual in values.items():
        if key == SETTINGS and name == "InstallerLanguage":
            if type(actual) is not str or actual not in ("1033", "1049"):
                return False
            continue
        wanted = (settings if key == SETTINGS else uninstall).get(name)
        if type(actual) is not type(wanted) or actual != wanted or wanted is None:
            return False
    return True


def registry_snapshot():
    return {(key, view): registry_key(key, view) for view in registry_views() for key in (UNINSTALL, SETTINGS)}


def verify_uninstall_registry(before, after):
    for (key, view), entry in after.items():
        old = before[key, view]
        if entry is None:
            continue
        require(key == SETTINGS and old is not None and entry == (
            0, {name: value for name, value in old[1].items() if name != "InstallDir"}
        ), "uninstall_registration_remains")


def clean_registry(install, proven_residue):
    import winreg

    state = registry_snapshot()
    for (key, view), entry in state.items():
        require(owned_registry(key, entry, install) or entry == proven_residue.get((key, view)),
                "unexpected_registry_owner")
    for (key, view), entry in state.items():
        current = registry_key(key, view)
        if current is not None:  # Views may map to the same key.
            require(current == entry, "registry_changed_before_cleanup")
            winreg.DeleteKeyEx(winreg.HKEY_CURRENT_USER, key, view, 0)


def verified_shortcuts(shortcuts, destination):
    require(preflight.path_status(shortcuts) == "directory", "installed_shortcuts_mismatch")
    names = contents(shortcuts)
    require(names == SHORTCUTS.keys(), "installed_shortcuts_mismatch")
    for name in names:
        require(preflight.path_status(shortcuts / name) == "regular_file",
                "installed_shortcut_type_mismatch")
    # Read each existing link without saving it. Invoke the trusted Windows
    # binary with an inline command so the configured script policy is kept.
    system = Path(os.environ.get("SystemRoot", ""))
    require(system.is_absolute(), "shortcut_query_unavailable")
    powershell = system / "System32/WindowsPowerShell/v1.0/powershell.exe"
    require(preflight.path_status(powershell) == "regular_file", "shortcut_query_unavailable")
    script = ("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
              "$shell=New-Object -ComObject WScript.Shell;"
              "$items=[ordered]@{}; Get-ChildItem -LiteralPath $env:FLOWBRIDGE_QA_LINKS -File | "
              "ForEach-Object {$link=$shell.CreateShortcut($_.FullName);"
              "$items[$_.Name]=@{target=$link.TargetPath;arguments=$link.Arguments}};"
              "$items | ConvertTo-Json -Compress")
    env = dict(os.environ, FLOWBRIDGE_QA_LINKS=str(shortcuts))
    data = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", script],
                          env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    require(data.returncode == 0, "shortcut_query_failed")
    try:
        targets = json.loads(data.stdout)
    except ValueError:
        raise preflight.Blocked("shortcut_query_invalid") from None
    require(isinstance(targets, dict) and targets.keys() == names
            and all(isinstance(targets[name], dict) and isinstance(targets[name].get("target"), str)
                    and Path(targets[name]["target"]) == destination / SHORTCUTS[name]
                    and targets[name].get("arguments") == "" for name in names),
            "installed_shortcut_targets_or_arguments_mismatch")


class Lifecycle:
    def __init__(self, kernel, args, pins, candidate, report):
        self.kernel = kernel
        self.candidate = args.candidate_root
        self.pins = pins
        self.payload = candidate["manifest_payload"]
        self.report = report
        self.work = Path(preflight.PRIVATE) / ("qa-beta4-" + uuid.uuid4().hex)
        self.temp = self.work / "tmp"
        self.install = self.work / "FlowBridge Тест QA With Spaces"
        self.alternate = self.work / "Must Not Relocate"
        self.marker = self.install / PRESERVE
        self.installer = self.candidate / "artifacts" / preflight.INSTALLER
        local, programs = preflight.known_folders()
        self.profile = local / "FlowBridgeExplicitBeta"
        self.shortcuts = programs / "FlowBridge Explicit Beta"
        self.directories = {}
        self.files = {}
        self.registered = {}
        self.uninstall_residue = {}
        self.started = False
        self.env = dict(os.environ, TEMP=str(self.temp), TMP=str(self.temp))

    def mark(self, phase):
        self.report["checks"][phase] = "PASS"

    def command(self, executable, arguments, timeout, *, raw=False, capture=False):
        cmdline = f'"{executable}" {arguments}' if raw else [str(executable), *arguments]
        result = subprocess.run(cmdline, executable=str(executable), cwd=self.work, env=self.env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        require(result.returncode == 0, "subprocess_nonzero_exit")
        if capture:
            try:
                output = json.loads(result.stdout)
            except ValueError:
                raise preflight.Blocked("installed_cli_invalid_json") from None
            require(isinstance(output, dict), "installed_cli_invalid_json")
            return output
        return None

    def verify_install(self, include_marker=False):
        expected_registry = known_registry(self.install)[1]
        view = registry_views()[0]
        state = registry_snapshot()
        require(all(owned_registry(key, entry, self.install) for (key, _), entry in state.items())
                and state[SETTINGS, view] is not None and state[UNINSTALL, view] == (0, expected_registry),
                "install_registration_mismatch")
        for path in (self.shortcuts, self.install):
            identity = directory_id(path)
            require(path not in self.directories or self.directories[path] == identity,
                    "installed_directory_identity_changed")
        verified_shortcuts(self.shortcuts, self.install)
        self.directories[self.shortcuts] = directory_id(self.shortcuts)
        for name in SHORTCUTS:
            self.files[self.shortcuts / name] = file_snapshot(self.shortcuts / name)
        expected = set(self.payload) | set(INSTALL_SUBDIRS) | {"Uninstall.exe"}
        if include_marker:
            expected.add(PRESERVE)
        require(contents(self.install) == expected, "installed_payload_inventory_mismatch")
        directories = {path: directory_id(path) for path in
                       [self.install, *(self.install / name for name in INSTALL_SUBDIRS)]}
        require(all(path not in self.directories or self.directories[path] == identity
                    for path, identity in directories.items()), "installed_payload_directory_changed")
        files = {}
        for name, pin in self.payload.items():
            file = self.install / name
            record = file_snapshot(file, pin["bytes"])
            require(record[3] == pin["sha256"], "installed_payload_hash_mismatch")
            files[file] = record
        uninstaller = self.install / "Uninstall.exe"
        files[uninstaller] = file_snapshot(uninstaller)
        self.directories.update(directories)
        self.files.update(files)
        self.registered = state

    def recheck_install_owner(self, *, repair_removed=False):
        require(preflight.process_count(self.kernel) == 0, "unexpected_product_process")
        for path in (self.work, self.temp, self.install, self.shortcuts,
                     *(self.install / name for name in INSTALL_SUBDIRS)):
            require(directory_id(path) == self.directories[path], "install_owner_directory_changed")
        for name in self.payload:
            path = self.install / name
            if repair_removed and name == REPAIR:
                require(preflight.path_status(path) == "absent", "reinstall_control_file_present")
            else:
                verify_recorded_file(path, self.files)
        for path in (self.install / "Uninstall.exe", *(self.shortcuts / name for name in SHORTCUTS)):
            verify_recorded_file(path, self.files)
        require(registry_snapshot() == self.registered, "install_owner_registration_changed")

    def install_to(self, destination):
        preflight.verified_digest(self.installer, self.pins["installer"])
        require(destination in (self.install, self.alternate) and destination.parent == self.work
                and directory_id(self.work) == self.directories[self.work]
                and directory_id(self.temp) == self.directories[self.temp] and empty(self.temp)
                and preflight.path_status(destination) == "absent", "unsafe_nsis_destination")
        if self.started:
            self.recheck_install_owner(repair_removed=True)
            baseline = None
        else:
            baseline = require_clean(self.kernel)
            self.mark("clean_baseline")
        self.started = True
        # NSIS requires an unquoted /D value as the last argument.
        self.command(self.installer, f"/S /D={destination}", 100, raw=True)
        wait_for(lambda: preflight.path_status(self.install / "Uninstall.exe") == "regular_file",
                 "install_completion_timeout")
        wait_for(lambda: empty(self.temp), "install_private_temp_not_drained")
        return baseline

    def verify_synthetic(self):
        require(directory_id(self.profile) == self.directories[self.profile]
                and contents(self.profile) == {"profile.json", "desktop-settings.json"},
                "test_profile_directory_or_contents_changed")
        for path in (self.profile / "profile.json", self.profile / "desktop-settings.json", self.marker):
            verify_recorded_file(path, self.files)

    def execute(self):
        require(preflight.path_status(self.work.parent) == "directory"
                and preflight.path_status(self.profile.parent) == "directory"
                and preflight.path_status(self.shortcuts.parent) == "directory", "unsafe_qa_parent")
        private_directory(self.work, self.kernel)
        self.directories[self.work] = directory_id(self.work)
        self.report["private_work_id"] = self.work.name
        self.temp.mkdir()
        self.directories[self.temp] = directory_id(self.temp)
        baseline = self.install_to(self.install)
        self.verify_install()
        self.mark("install")
        self.mark("payload")
        cli = self.install / "flowbridge-cli.exe"
        caps = self.command(cli, ["capabilities"], 15, capture=True)
        require(caps.get("version") == preflight.VERSION
                and caps.get("mode") == "explicit_loopback_socks5" and caps.get("tcp") is True
                and all(caps.get(key) is False for key in ("transparent_interception", "system_dns_interception",
                                                         "system_kill_switch", "udp", "quic")),
                "installed_capabilities_mismatch")
        profile_input = self.install / REPAIR
        validation = self.command(cli, ["validate", "--config", str(profile_input)], 15, capture=True)
        require(validation.get("ok") is True and validation.get("explicit_socks_compatible") is True,
                "installed_cli_validation_failed")
        self.mark("cli")
        verify_recorded_file(profile_input, self.files)
        profile_bytes = profile_input.read_bytes()
        require(hashlib.sha256(profile_bytes).hexdigest() == self.files[profile_input][3],
                "test_profile_source_changed")
        private_directory(self.profile, self.kernel)
        self.directories[self.profile] = directory_id(self.profile)
        write_fixture(self.profile / "profile.json", profile_bytes, self.files)
        write_fixture(self.profile / "desktop-settings.json",
                      b'{"version":1,"managed_ssh":false,"ssh_workers":1}\n', self.files)
        write_fixture(self.marker, b"Preserve this unrelated synthetic QA file.\n", self.files)

        # A successful reinstall must restore an absent verified payload file.
        self.recheck_install_owner()
        profile_input.unlink()
        self.install_to(self.alternate)
        self.verify_install(include_marker=True)
        require(preflight.path_status(self.alternate) == "absent", "reinstall_relocated")
        self.verify_synthetic()
        self.mark("reinstall")

        uninstaller = self.install / "Uninstall.exe"
        self.recheck_install_owner()
        self.command(uninstaller, ["/S"], 45)
        wait_for(lambda: preflight.path_status(uninstaller) == "absent"
                 and all(registry_key(UNINSTALL, view) is None for view in registry_views())
                 and empty(self.temp), "uninstall_completion_timeout")
        require(contents(self.install) == {PRESERVE}
                and preflight.path_status(self.shortcuts) == "absent", "uninstall_payload_remains")
        residue = registry_snapshot()
        verify_uninstall_registry(self.registered, residue)
        self.uninstall_residue = residue
        self.mark("uninstall")
        self.verify_synthetic()
        self.mark("profile_preserved")
        require(preflight.installed_state(self.kernel)["stable"] == baseline["stable"]
                and all(registry_key(key, view) is None for view in registry_views() for key in
                        (r"Software\FlowBridge", r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridge")),
                "stable_baseline_changed")
        self.mark("stable_preserved")

    def cleanup(self):
        if self.work not in self.directories:
            return
        require(directory_id(self.work) == self.directories[self.work], "work_directory_identity_changed")
        if self.started:
            require(preflight.process_count(self.kernel) == 0, "cleanup_product_process_still_running")
            # A copied NSIS uninstaller may outlive its bootstrapper. The private
            # TEMP must drain before altering registry/files that it may be using.
            wait_for(lambda: empty(self.temp), "cleanup_private_temp_not_drained", timeout=15)
        failures = {}
        actions = {"work": lambda: remove_owned_tree(self.work, self.directories, self.files)}
        if self.started:
            actions = {"profile": lambda: remove_owned_tree(self.profile, self.directories, self.files)
                       if self.profile in self.directories else None,
                       "shortcuts": lambda: remove_owned_tree(self.shortcuts, self.directories, self.files),
                       "registry": lambda: clean_registry(self.install, self.uninstall_residue),
                       **actions}
        for step, action in actions.items():
            try:
                action()
            except (preflight.Blocked, OSError, subprocess.SubprocessError) as error:
                failures[step] = str(error) if isinstance(error, preflight.Blocked) else type(error).__name__
        if failures:
            self.report["cleanup_failures"] = failures
            return
        require_clean(self.kernel)
        self.mark("cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", required=True, type=Path)
    for name in preflight.PIN_FIELDS:
        parser.add_argument("--expected-" + name + ("" if name in ("source", "tree") else "-sha256"),
                            dest=name, required=True)
    args = parser.parse_args()
    pins = {name: getattr(args, name) for name in preflight.PIN_FIELDS}
    report = {"schema": "flowbridge-win11-beta4-headless-lifecycle-v1",
              "checks": dict.fromkeys(CHECKS, "NOT_RUN"),
              "gui_acceptance": "NOT_RUN", "visual_acceptance": "NOT_RUN",
              "gui_managed_ssh": "NOT_RUN"}
    lifecycle = None
    try:
        require(sys.platform == "win32", "wrong_execution_platform")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        report["host"] = preflight.windows_host(kernel)
        session = preflight.current_session(kernel)
        require(session == 0 and report["host"]["token_elevated"], "requires_elevated_lab_session_zero")
        report["session"] = session
        require_clean(kernel)
        candidate = preflight.probe_candidate(args.candidate_root, pins)
        evidence_sha = verify_runner_result(args.candidate_root, pins, candidate["manifest_payload"])
        report["candidate"] = {"version": candidate["version"], "pins": pins,
                               "runner_result_sha256": evidence_sha}
        lifecycle = Lifecycle(kernel, args, pins, candidate, report)
        lifecycle.execute()
    except (preflight.Blocked, OSError, subprocess.SubprocessError) as error:
        report["failure"] = str(error) if isinstance(error, preflight.Blocked) else type(error).__name__
    finally:
        if lifecycle is not None:
            try:
                lifecycle.cleanup()
            except (preflight.Blocked, OSError, subprocess.SubprocessError) as error:
                report["cleanup_failure"] = (str(error) if isinstance(error, preflight.Blocked)
                                             else type(error).__name__)
    passed = all(value == "PASS" for value in report["checks"].values()) and "failure" not in report
    report["status"] = "PASS_HEADLESS_LIFECYCLE" if passed else "FAILED_OR_BLOCKED"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
