#!/usr/bin/env python3
"""Read-only Win11 beta.4 host, desktop, isolation and optional candidate preflight."""
from __future__ import annotations

import argparse
import csv
import ctypes
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import socket
import stat
import subprocess
import sys

HOST = "VM-326272"
ACCOUNT = HOST + r"\Admin"
BUILD = 22631
VERSION = "0.3.0-beta.4"
PRIVATE = PureWindowsPath(r"C:\FlowBridge\private-candidates")
INSTALLER = f"FlowBridge-{VERSION}-windows-x64-setup.exe"
PAYLOAD = {
    "FlowBridge.exe", "flowbridge-cli.exe", "flowbridge_ffi.dll", "LICENSE", "README.txt",
    "SBOM.cdx.json", "BUILD-METADATA.json", "licenses/THIRD_PARTY_NOTICES.txt",
    "licenses/nlohmann-json-LICENSE.MIT", "resources/presets.json",
    "examples/direct.json", "examples/ssh-socks.json", "examples/chain.json",
}
PIN_FIELDS = ("source", "tree", "installer", "manifest", "harness", "tool")


class Blocked(RuntimeError):
    """A fixed preflight reason that never embeds local paths or contents."""


def require(condition, code):
    if not condition:
        raise Blocked(code)


def candidate_root(path):
    parts = path.parts
    require(len(parts) == len(PRIVATE.parts) + 2 and path.parent.parent == PRIVATE
            and path.name == "candidate"
            and re.fullmatch(r"run-beta4-[1-9][0-9]*-[1-9][0-9]*", path.parent.name),
            "candidate_outside_beta4_run")
    return path


def check_pins(pins):
    for name in PIN_FIELDS:
        length = 40 if name in ("source", "tree") else 64
        require(re.fullmatch(f"[0-9a-f]{{{length}}}", pins[name]) is not None,
                "invalid_expected_pin")


def validate_manifest(manifest, pins):
    require(isinstance(manifest, dict), "invalid_manifest")
    expected = {
        "schema": "flowbridge-explicit-beta-windows-qa-package-v1",
        "candidate": VERSION,
        "source_sha": pins["source"],
        "source_tree_sha": pins["tree"],
        "installer_sha256": pins["installer"],
        "explicit_socks_only": True,
        "gui_protected_ui_compiled_disabled": True,
        "driver_included": False,
        "capture_helper_included": False,
        "system_service_included": False,
        "signed": False,
        "publisher_release_approved": False,
        "profile_namespace": "FlowBridgeExplicitBeta",
        "uninstall_registration": "FlowBridgeExplicitBeta",
    }
    for key, value in expected.items():
        actual = manifest.get(key)
        require(type(actual) is type(value) and actual == value, "manifest_contract_" + key)
    entries = manifest.get("payload")
    require(isinstance(entries, list) and len(entries) == len(PAYLOAD), "payload_allowlist_mismatch")
    payload = {}
    for item in entries:
        require(isinstance(item, dict), "invalid_payload_entry")
        name, sha, size = item.get("path"), item.get("sha256"), item.get("bytes")
        require(isinstance(name, str) and name in PAYLOAD and name not in payload,
                "payload_allowlist_mismatch")
        require(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)
                and type(size) is int and size > 0, "invalid_payload_entry")
        payload[name] = {"sha256": sha, "bytes": size}
    installer_size = manifest.get("installer_bytes")
    harness = manifest.get("qa_harness")
    require(type(installer_size) is int and installer_size > 0, "invalid_installer_size")
    require(isinstance(harness, dict) and harness.get("sha256") == pins["harness"]
            and type(harness.get("bytes")) is int and harness["bytes"] > 0, "harness_pin_mismatch")
    return installer_size, harness["bytes"], payload


def path_status(path):
    """Inspect fixed components using metadata only, stopping before any reparse point."""
    for item in (*reversed(path.parents), path):
        try:
            details = item.lstat()
        except FileNotFoundError:
            return "absent"
        if stat.S_ISLNK(details.st_mode) or getattr(details, "st_file_attributes", 0) & 0x400:
            return "reparse"
        if not stat.S_ISDIR(details.st_mode):
            return "regular_file" if item == path and stat.S_ISREG(details.st_mode) else "unexpected"
    return "directory"


def verified_digest(path, want, size=None, *, read_manifest=False):
    require(path_status(path) == "regular_file", "candidate_file_absent_or_unsafe")
    with path.open("rb") as stream:
        if read_manifest:
            data = stream.read(262145)
            require(len(data) <= 262144, "manifest_too_large")
            actual = hashlib.sha256(data).hexdigest()
        else:
            digest = hashlib.sha256()
            byte_count = 0
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                byte_count += len(chunk)
                require(size is None or byte_count <= size, "candidate_file_size_mismatch")
                digest.update(chunk)
            require(size is None or byte_count == size, "candidate_file_size_mismatch")
            actual = digest.hexdigest()
            data = None
    require(actual == want, "candidate_file_hash_mismatch")
    return data


def probe_candidate(root, pins):
    candidate_root(PureWindowsPath(root))
    check_pins(pins)
    data = verified_digest(root / "build/verification/explicit-beta-package.json",
                           pins["manifest"], read_manifest=True)
    try:
        manifest = json.loads(data)
    except (ValueError, UnicodeError):
        raise Blocked("invalid_manifest") from None
    installer_size, harness_size, payload = validate_manifest(manifest, pins)
    verified_digest(root / "artifacts" / INSTALLER, pins["installer"], installer_size)
    verified_digest(root / "build/windows-explicit-beta/Release/FlowBridgeNativeSmoke.exe",
                    pins["harness"], harness_size)
    verified_digest(root / "tools/explicit_beta_acceptance.py", pins["tool"])
    return {"status": "VERIFIED_BYTES", "version": VERSION, "pins": pins,
            "manifest_payload": payload, "payload_bytes_verified": False}


def api(library, name, result, *arguments):
    fn = getattr(library, name)
    fn.restype, fn.argtypes = result, arguments
    return fn


def windows_host(kernel):
    import winreg

    version = sys.getwindowsversion()
    require(socket.gethostname().casefold() == HOST.casefold(), "wrong_computer")
    require((version.major, version.minor, version.build, version.product_type) ==
            (10, 0, BUILD, 1), "wrong_win11_build")
    process, native = w.USHORT(), w.USHORT()
    current = api(kernel, "GetCurrentProcess", w.HANDLE)()
    query = api(kernel, "IsWow64Process2", w.BOOL, w.HANDLE,
                ctypes.POINTER(w.USHORT), ctypes.POINTER(w.USHORT))
    require(query(current, ctypes.byref(process), ctypes.byref(native))
            and process.value == 0 and native.value == 0x8664, "not_native_amd64_python")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                        0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        edition = winreg.QueryValueEx(key, "EditionID")[0]
        ubr = winreg.QueryValueEx(key, "UBR")[0]
    require(edition == "Professional" and type(ubr) is int, "wrong_win11_edition")
    system = ctypes.create_unicode_buffer(32768)
    length = api(kernel, "GetSystemDirectoryW", w.UINT, w.LPWSTR, w.UINT)(system, len(system))
    require(0 < length < len(system), "windows_system_directory_query_failed")
    whoami = subprocess.run([str(Path(system.value) / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
                            capture_output=True, text=True, timeout=10, check=False)
    rows = list(csv.reader(whoami.stdout.splitlines()))
    require(whoami.returncode == 0 and len(rows) == 1 and len(rows[0]) == 2
            and rows[0][0].casefold() == ACCOUNT.casefold(), "wrong_account")
    elevated = bool(api(ctypes.WinDLL("shell32"), "IsUserAnAdmin", w.BOOL)())
    return {"computer": HOST, "account": ACCOUNT, "os": "Windows 11 Pro",
            "build": BUILD, "ubr": ubr, "architecture": "x64", "token_elevated": elevated}


def current_session(kernel):
    session = w.DWORD()
    pid = api(kernel, "GetCurrentProcessId", w.DWORD)()
    require(api(kernel, "ProcessIdToSessionId", w.BOOL, w.DWORD, ctypes.POINTER(w.DWORD))(
        pid, ctypes.byref(session)), "session_id_query_failed")
    return session.value


def active_sessions():
    class Session(ctypes.Structure):
        _fields_ = [("id", w.DWORD), ("station", w.LPWSTR), ("state", ctypes.c_int)]

    wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
    memory = ctypes.POINTER(Session)()
    count = w.DWORD()
    enumerate_sessions = api(wts, "WTSEnumerateSessionsW", w.BOOL, w.HANDLE, w.DWORD, w.DWORD,
                             ctypes.POINTER(ctypes.POINTER(Session)), ctypes.POINTER(w.DWORD))
    query = api(wts, "WTSQuerySessionInformationW", w.BOOL, w.HANDLE, w.DWORD, ctypes.c_int,
                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(w.DWORD))
    free = api(wts, "WTSFreeMemory", None, ctypes.c_void_p)

    def query_string(session, field):
        value, size = ctypes.c_void_p(), w.DWORD()
        require(query(None, session, field, ctypes.byref(value), ctypes.byref(size)),
                "active_session_identity_query_failed")
        try:
            return ctypes.wstring_at(value) if value and size.value > 2 else ""
        finally:
            free(value)

    require(enumerate_sessions(None, 0, 1, ctypes.byref(memory), ctypes.byref(count)),
            "session_enumeration_failed")
    try:
        result = []
        for item in memory[:count.value]:
            if item.id == 0 or item.state != 0:  # WTSActive
                continue
            name = query_string(item.id, 5)  # WTSUserName
            domain = query_string(item.id, 7)  # WTSDomainName
            result.append({"id": item.id, "target_account": f"{domain}\\{name}".casefold() == ACCOUNT.casefold()})
        return sorted(result, key=lambda item: item["id"])
    finally:
        free(memory)


def input_desktop(kernel):
    user = ctypes.WinDLL("user32", use_last_error=True)
    get_info = api(user, "GetUserObjectInformationW", w.BOOL, w.HANDLE, ctypes.c_int,
                   ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD))

    def object_name(handle):
        string = ctypes.create_unicode_buffer(256)
        length = w.DWORD()
        return (string.value if get_info(handle, 2, string, ctypes.sizeof(string), ctypes.byref(length))
                else "")  # UOI_NAME

    station = api(user, "GetProcessWindowStation", w.HANDLE)()
    thread = api(kernel, "GetCurrentThreadId", w.DWORD)()
    thread_desktop = api(user, "GetThreadDesktop", w.HANDLE, w.DWORD)(thread)
    if object_name(station).casefold() != "winsta0" or object_name(thread_desktop).casefold() != "default":
        return False, None
    desktop = api(user, "OpenInputDesktop", w.HANDLE, w.DWORD, w.BOOL, w.DWORD)(
        0, False, 0x0001)  # DESKTOP_READOBJECTS only
    if not desktop:
        return False, None
    try:
        get_metrics = api(user, "GetSystemMetrics", ctypes.c_int, ctypes.c_int)
        width, height = get_metrics(0), get_metrics(1)
        ready = object_name(desktop).casefold() == "default" and width > 0 and height > 0
        return ready, {"width": width, "height": height} if ready else None
    finally:
        api(user, "CloseDesktop", w.BOOL, w.HANDLE)(desktop)


def desktop_status(session, sessions, accessible):
    if session == 0:
        return "BLOCKED_SESSION_0"
    if not any(item["id"] == session and item["target_account"] for item in sessions):
        return "BLOCKED_SESSION_NOT_ACTIVE_FOR_ACCOUNT"
    return "INTERACTIVE_DESKTOP_OBSERVED" if accessible else "BLOCKED_INPUT_DESKTOP_UNAVAILABLE"


def process_count(kernel):
    class Entry(ctypes.Structure):
        _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("pid", w.DWORD),
                    ("heap", ctypes.c_size_t), ("module", w.DWORD), ("threads", w.DWORD),
                    ("parent", w.DWORD), ("priority", w.LONG), ("flags", w.DWORD),
                    ("exe", w.WCHAR * 260)]

    snapshot = api(kernel, "CreateToolhelp32Snapshot", w.HANDLE, w.DWORD, w.DWORD)(2, 0)
    require(snapshot not in (None, ctypes.c_void_p(-1).value), "process_enumeration_failed")
    names = {"flowbridge.exe", "flowbridgecapture.exe", "flowbridge-cli.exe", "flowbridgenativesmoke.exe"}
    entry = Entry()
    entry.size = ctypes.sizeof(entry)
    first = api(kernel, "Process32FirstW", w.BOOL, w.HANDLE, ctypes.POINTER(Entry))
    next_entry = api(kernel, "Process32NextW", w.BOOL, w.HANDLE, ctypes.POINTER(Entry))
    try:
        require(first(snapshot, ctypes.byref(entry)), "process_enumeration_failed")
        count = 0
        while True:
            count += entry.exe.casefold() in names
            if not next_entry(snapshot, ctypes.byref(entry)):
                require(ctypes.get_last_error() == 18, "process_enumeration_failed")
                return count
    finally:
        api(kernel, "CloseHandle", w.BOOL, w.HANDLE)(snapshot)


def known_folders():
    import uuid

    shell, ole = ctypes.WinDLL("shell32"), ctypes.WinDLL("ole32")
    get_folder = api(shell, "SHGetKnownFolderPath", ctypes.c_long, ctypes.c_void_p, w.DWORD,
                     w.HANDLE, ctypes.POINTER(ctypes.c_void_p))
    free = api(ole, "CoTaskMemFree", None, ctypes.c_void_p)

    def folder(guid):
        value = ctypes.c_void_p()
        identifier = (ctypes.c_byte * 16).from_buffer_copy(uuid.UUID(guid).bytes_le)
        try:
            # KF_FLAG_DONT_VERIFY avoids creating or verifying a missing folder.
            require(get_folder(identifier, 0x4000, None, ctypes.byref(value)) == 0 and value,
                    "known_folder_query_failed")
            path = Path(ctypes.wstring_at(value))
            require(re.fullmatch(r"[A-Za-z]:", path.drive) and path.is_absolute(),
                    "nonlocal_known_folder")
            return path
        finally:
            free(value)

    return (folder("F1B32785-6FBA-4FCF-9D55-7B8E7F157091"),
            folder("A77F5D77-2E2B-44C3-A6A2-ABA601054A51"))  # LocalAppData, Programs


def installed_state(kernel):
    import winreg

    def registry(key, view, field=None):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_READ | view) as handle:
                if field is not None:
                    winreg.QueryValueEx(handle, field)
                return True
        except FileNotFoundError:
            return False

    local, programs = known_folders()
    state = {}
    for name, namespace, label in (("stable", "FlowBridge", "FlowBridge"),
                                   ("beta", "FlowBridgeExplicitBeta", "FlowBridge Explicit Beta")):
        profile = local / namespace
        settings = rf"Software\{namespace}"
        uninstall = rf"Software\Microsoft\Windows\CurrentVersion\Uninstall\{namespace}"
        state[name] = {
            "profile_directory": path_status(profile),
            "profile_file": path_status(profile / "profile.json"),
            "desktop_settings_file": path_status(profile / "desktop-settings.json"),
            "default_install_directory": path_status(local / "Programs" / label),
            "shortcuts_directory": path_status(programs / label),
            "registry": {
                architecture: {"install_dir_value": registry(settings, view, "InstallDir"),
                               "installer_language_value": registry(settings, view, "InstallerLanguage"),
                               "uninstall_key": registry(uninstall, view)}
                for architecture, view in (("64", winreg.KEY_WOW64_64KEY), ("32", winreg.KEY_WOW64_32KEY))
            },
        }
    state["flowbridge_process_count"] = process_count(kernel)
    return state


def isolation_status(state):
    if state["flowbridge_process_count"]:
        return "BLOCKED_RUNNING_FLOWBRIDGE"
    beta = state["beta"]
    for record in beta["registry"].values():
        if record["install_dir_value"] or record["uninstall_key"]:
            return "BLOCKED_EXISTING_BETA_REGISTRATION"
    for name in ("profile_directory", "profile_file", "desktop_settings_file",
                 "default_install_directory", "shortcuts_directory"):
        if beta[name] != "absent":
            return "BLOCKED_EXISTING_OR_UNSAFE_BETA_PATH"
    return "ISOLATION_BASELINE_AVAILABLE"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path)
    for name in PIN_FIELDS:
        parser.add_argument("--expected-" + name + ("" if name in ("source", "tree") else "-sha256"),
                            dest=name)
    args = parser.parse_args()
    pins = {name: getattr(args, name) for name in PIN_FIELDS}
    report = {"schema": "flowbridge-win11-explicit-beta-preflight-v1",
              "candidate": {"status": "NOT_CHECKED"},
              "native_acceptance": "NOT_RUN", "visual_acceptance": "NOT_RUN"}
    try:
        require((args.candidate_root is None and all(value is None for value in pins.values()))
                or (args.candidate_root is not None and all(value is not None for value in pins.values())),
                "candidate_root_and_all_expected_pins_required")
        require(sys.platform == "win32", "wrong_execution_platform")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        report["host"] = windows_host(kernel)
        session, sessions = current_session(kernel), active_sessions()
        desktop, metrics = input_desktop(kernel) if session != 0 else (False, None)
        report["desktop"] = {
            "process_session": session, "active_sessions": sessions, "screen_pixels": metrics,
            "status": desktop_status(session, sessions, desktop),
        }
        state = installed_state(kernel)
        report["per_user_state"] = state
        report["isolation"] = isolation_status(state)
        if args.candidate_root is not None:
            report["candidate"] = probe_candidate(args.candidate_root, pins)
        report["status"] = "READ_ONLY_CHECKS_COMPLETED"
        result = 0
    except Blocked as error:
        report.update(status="BLOCKED", reason=str(error))
        result = 1
    except (OSError, subprocess.SubprocessError):
        report.update(status="BLOCKED", reason="native_query_or_read_failed")
        result = 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
