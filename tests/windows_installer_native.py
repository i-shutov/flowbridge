#!/usr/bin/env python3
"""Install, exercise, upgrade and uninstall on an isolated native Windows CI user.

Refuses non-CI machines and any pre-existing registered FlowBridge installation.
The installed GUI is tested through the real Win32/network integration harness.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, **kwargs):
    print("RUN", command, flush=True)
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=180, **kwargs)
    text = result.stdout.decode("utf-8", errors="replace")
    print(text, flush=True)
    return text


def wait_until(predicate, message):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise RuntimeError(message)


def main():
    require(sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_OS") == "Windows",
            "This test requires a disposable GitHub-hosted Windows runner")
    import winreg

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    installer = Path(manifest["installer"]).resolve()
    uninstall_key = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridge"
    settings_key = r"Software\FlowBridge"

    def value(key, name):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
                return winreg.QueryValueEx(handle, name)[0]
        except FileNotFoundError:
            return None

    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, uninstall_key, 0,
                                winreg.KEY_READ | view):
                raise RuntimeError("Refusing to alter an existing installation")
        except FileNotFoundError:
            pass
    require(value(settings_key, "InstallDir") is None, "Existing InstallDir registration")
    require(digest(installer) == manifest["sha256"], "Installer hash mismatch")
    require(installer.stat().st_size == manifest["bytes"], "Installer size mismatch")
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"platform": "native Windows", "installer_sha256": manifest["sha256"],
              "commit": os.environ.get("GITHUB_SHA"), "passed": False, "checks": []}

    def passed(name):
        print("PASS", name, flush=True)
        report["checks"].append(name)

    root = Path(tempfile.mkdtemp(prefix="flowbridge-install-", dir=os.environ["RUNNER_TEMP"]))
    install = root / "FlowBridge тест с пробелами"
    alternate = root / "must-not-move"

    def install_to(destination):
        # NSIS /D must be the final argument, and must NOT be quoted, even with spaces.
        command = f'"{installer}" /S /D={destination}'
        run(command, executable=str(installer))
        wait_until(lambda: (install / "Uninstall.exe").is_file(), "Installation did not complete")
        for entry in manifest["payload"]:
            path = install / entry["path"]
            require(path.is_file() and digest(path) == entry["sha256"],
                    "Installed payload mismatch: " + entry["path"])

    try:
        install_to(install)
        require(value(settings_key, "InstallDir") == str(install), "Wrong registered path")
        require(value(uninstall_key, "InstallLocation") == str(install), "Missing uninstall entry")
        shortcuts = Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/FlowBridge"
        require(len(list(shortcuts.glob("*.lnk"))) == 3, "Expected three Start menu shortcuts")
        passed("Unicode/spaced install path, all payload hashes, registry and shortcuts")
        json.loads(run([str(install / "flowbridge-cli.exe"), "capabilities"]).strip())
        validated = json.loads(run([str(install / "flowbridge-cli.exe"), "validate", "--config",
                                    str(install / "examples/direct.json")]).strip())
        require(validated["ok"] is True, "Installed CLI validation failed")
        passed("Installed CLI starts and validates a real profile")
        # The native helper is included, but no unsigned WFP driver is installed.
        capture = install / "FlowBridgeCapture.exe"
        preflight = json.loads(run([str(capture), "--preflight"]).strip())
        require(preflight["product"] == "FlowBridgeCapture" and preflight["native_helper"] is True,
                "Native helper preflight did not respond")
        require(preflight["driver_auto_installed"] is False and
                preflight["redirect_runtime_tested"] is False,
                "Installer falsely claims the kernel redirect is accepted")
        passed("Installed elevated capture helper exposes an honest read-only driver preflight")
        require(preflight.get("kernel_driver_accessible") in (True, False),
                "Native driver probe returned an invalid boolean")
        # Trust-boundary regression on the REAL installed helper, independent
        # of whether a signed kernel driver is available on hosted CI.
        rejected_ssh = subprocess.run(
            [str(capture), "--console", "--profile", str(install / "examples/direct.json"),
             "--capture-app", str(install / "FlowBridge.exe"),
             "--gui-owner", str(os.getpid()),
             "--stop-event", "Local\\FlowBridgeCaptureStop-QA",
             "--ssh-profile", str(install / "examples/direct.json")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10, text=True)
        require(rejected_ssh.returncode != 0 and
                "GUI-owned capture must reuse the unelevated SSH session" in rejected_ssh.stdout,
                "Installed privileged helper accepted GUI-owned SSH execution")
        passed("Installed helper refuses privileged SSH launch for GUI-owned capture")
        # Create a genuine user-owned stop event so the installed helper reaches
        # its profile digest guard. The wrong digest must fail before any WFP
        # device/open or network redirect, even without a test driver.
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                        ctypes.c_int, ctypes.c_wchar_p]
        kernel.CreateEventW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        stop_name = "Local\\FlowBridgeCaptureStop-InstallerQA-" + str(os.getpid())
        event = kernel.CreateEventW(None, True, False, stop_name)
        require(event, "Could not create installer QA stop event")
        try:
            invalid_digest = subprocess.run(
                [str(capture), "--console", "--profile",
                 str(install / "examples/direct.json"), "--capture-app",
                 str(install / "FlowBridge.exe"), "--gui-owner", str(os.getpid()),
                 "--stop-event", stop_name, "--profile-sha256", "0" * 64],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=10, text=True)
            require(invalid_digest.returncode != 0 and
                    "GUI native profile SHA-256 mismatch" in invalid_digest.stdout,
                    "Installed helper accepted a modified profile across UAC")
        finally:
            kernel.CloseHandle(event)
        passed("Installed helper pins exact profile SHA-256 before opening the WFP driver")
        text = run([str(args.harness.resolve()), str(install / "FlowBridge.exe"),
                    str((args.output / "installed-ui.bmp").resolve())])
        require("PASS Win32 GUI" in text and "PASS Windows DLL" in text, "GUI smoke incomplete")
        require("PASS compact Windows GUI" in text, "Compact GUI geometry checks missing")
        snapshots = {}
        for page in ("dashboard", "ssh", "proxy", "apps", "advanced"):
            image = args.output / f"installed-ui-compact-{page}.bmp"
            pixels = image.read_bytes()
            require(len(pixels) >= 54 and pixels[:2] == b"BM",
                    f"Missing or malformed Win32 evidence screenshot: {page}")
            width, negative_height = struct.unpack_from("<ii", pixels, 18)
            height = abs(negative_height)
            require(width >= 920 and height >= 600 and
                    len(pixels) >= 54 + width * height * 4,
                    f"Truncated or out-of-bounds compact page screenshot: {page}")
            snapshots[page] = {"sha256": hashlib.sha256(pixels).hexdigest(),
                               "width": width, "height": height}
        require(len({snapshot["sha256"] for snapshot in snapshots.values()}) == len(snapshots),
                "At least two compact pages produced an identical screenshot")
        report["compact_ui_screenshots"] = snapshots
        passed("All five compact Win32 views have real monitor-bounded, full-client BMP evidence")
        passed("Installed native GUI and DLL: real TCP traffic, half-close, Apply/Start/Stop")
        profile = Path(os.environ["LOCALAPPDATA"]) / "FlowBridge/profile.json"
        profile_hash = digest(profile)
        keep = install / "user-notes.txt"
        keep.write_text("User-owned file: preserve.\n", encoding="utf-8")
        install_to(alternate)
        require(not alternate.exists(), "Upgrade unexpectedly moved the installation")
        require(digest(profile) == profile_hash and keep.is_file(), "Upgrade removed user data")
        passed("Upgrade retains registered location, user profile and unrelated files")
        run([str(install / "Uninstall.exe"), "/S"])
        wait_until(lambda: not (install / "FlowBridge.exe").exists()
                   and not (install / "Uninstall.exe").exists(), "Uninstall did not complete")
        require(all(not (install / item["path"]).exists() for item in manifest["payload"]),
                "Known payload remains after uninstall")
        require(value(uninstall_key, "DisplayName") is None, "Uninstall registration remains")
        require(value(settings_key, "InstallDir") is None, "InstallDir remains")
        require(not list(shortcuts.glob("*.lnk")), "Shortcuts remain")
        require(digest(profile) == profile_hash, "Uninstaller altered the user's profile")
        require(keep.read_text(encoding="utf-8") == "User-owned file: preserve.\n",
                "Uninstaller deleted an unrelated user file")
        passed("Actual uninstall cleans binaries/shortcuts/registry and preserves user data")
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (args.output / "native-installer-result.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
