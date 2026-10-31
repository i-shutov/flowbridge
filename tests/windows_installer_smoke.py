#!/usr/bin/env python3
"""Actual AMD64 NSIS install/upgrade/uninstall under an isolated Wine prefix.

Run under xvfb-run on Linux. No Windows-native or kernel validation is implied.
The prefix must be new or contain this test's ownership marker.
Keep the live prefix and output under /tmp when the workspace is mirrored; copy
the completed logs back only after this process exits.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prefix = args.prefix.resolve()
    marker = prefix / ".flowbridge-installer-smoke-owned"
    if prefix.exists() and any(prefix.iterdir()) and not marker.is_file():
        raise RuntimeError("Refusing an existing, unmarked Wine prefix")
    prefix.mkdir(parents=True, exist_ok=True)
    marker.write_text("Owned only by FlowBridge installer smoke test.\n")
    args.output.mkdir(parents=True, exist_ok=True)
    log_path = args.output / "windows-installer-smoke.txt"
    results_path = args.output / "windows-installer-results.json"
    manifest = json.loads(args.manifest.read_text())
    env = os.environ.copy()
    env.update(WINEPREFIX=str(prefix), WINEARCH="win64", WINEDEBUG="-all",
               WINEDLLOVERRIDES="winemenubuilder.exe=d")
    wine = "/usr/lib/wine/wine64"
    install_win = r"C:\FlowBridgeSmokeInstall"
    install = prefix / "drive_c/FlowBridgeSmokeInstall"
    alternate = prefix / "drive_c/FlowBridgeMustNotMove"
    uninstall_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridge"
    settings_key = r"HKCU\Software\FlowBridge"
    results = {"environment": "Wine64 on Linux; not native Windows or kernel validation",
               "prefix": str(prefix), "installer": str(args.installer.resolve()),
               "passed": False, "checks": []}

    with log_path.open("w", buffering=1) as log:
        def note(text):
            print(text, flush=True)
            log.write(text + "\n")

        def run(arguments, *, allow_failure=False, timeout=120):
            note("RUN " + subprocess.list2cmdline([str(x) for x in arguments]))
            completed = subprocess.run([str(x) for x in arguments], env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       timeout=timeout)
            output = completed.stdout.decode("utf-8", errors="replace")
            log.write(output + f"\nEXIT {completed.returncode}\n")
            if completed.returncode and not allow_failure:
                raise RuntimeError(f"Command failed ({completed.returncode}): {output}")
            return completed.returncode, output

        def passed(name, **details):
            note("PASS " + name)
            results["checks"].append({"name": name, "passed": True, **details})

        def digest(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()

        def query(key):
            found = []
            for view in ("64", "32"):
                code, output = run([wine, "reg.exe", "query", key, f"/reg:{view}"], allow_failure=True)
                if code == 0:
                    found.append(output)
            return "\n".join(found)

        def verify_payload():
            for entry in manifest["payload"]:
                path = install / entry["path"]
                assert path.is_file(), f"Missing installed payload: {entry['path']}"
                assert path.stat().st_size == entry["bytes"], f"Size mismatch: {entry['path']}"
                assert digest(path) == entry["sha256"], f"Hash mismatch: {entry['path']}"

        def wait_until(check, description, timeout=120):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if check():
                    return
                time.sleep(0.1)
            raise RuntimeError("Timed out: " + description)

        try:
            assert digest(args.installer) == manifest["sha256"], "Installer hash does not match final manifest"
            assert args.installer.stat().st_size == manifest["bytes"], "Installer size mismatch"
            passed("Final installer matches manifest", sha256=manifest["sha256"], bytes=manifest["bytes"])
            run([wine, "reg.exe", "add", r"HKCU\Software\Wine", "/v", "Version", "/t", "REG_SZ", "/d", "win10", "/f"])
            assert not query(uninstall_key), "Prefix already contains a registered FlowBridge installation"
            assert not install.exists() or sorted(p.name for p in install.iterdir()) == ["keep-me.txt"], "Test installation directory contains unexpected files"
            run([wine, args.installer.resolve(), "/S", "/D=" + install_win])
            wait_until(lambda: (install / "Uninstall.exe").is_file(), "initial install completion")
            verify_payload()
            assert install_win.lower() in query(uninstall_key).lower(), "Missing uninstall registration"
            assert install_win.lower() in query(settings_key).lower(), "Missing InstallDir registration"
            shortcuts = list((prefix / "drive_c/users").glob("*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/FlowBridge/*.lnk"))
            assert len(shortcuts) == 3, f"Expected three Start menu shortcuts, found {shortcuts}"
            passed("Silent install: payload hashes, registry, uninstaller and three Start menu shortcuts", payload_files=len(manifest["payload"]))
            _, output = run([wine, install / "flowbridge-cli.exe", "capabilities"])
            json.loads(output.strip())
            _, output = run([wine, install / "flowbridge-cli.exe", "validate", "--config", install_win + r"\examples\direct.json"])
            assert json.loads(output.strip())["ok"] is True
            passed("Installed CLI capabilities and actual profile validation")
            if args.harness:
                screenshot = args.output / "windows-installer-gui.bmp"
                _, output = run([wine, args.harness.resolve(), install_win + r"\FlowBridge.exe", screenshot.resolve()], timeout=150)
                assert "PASS Win32 GUI" in output and "PASS Windows DLL" in output
                passed("Installed GUI: real traffic, Apply/Start/Stop, metrics, edits, native export and clean exit", screenshot=str(screenshot))
            profiles = list((prefix / "drive_c/users").glob("*/AppData/Local/FlowBridge/profile.json"))
            assert len(profiles) == 1, "Expected profile persisted by installed GUI"
            profile = profiles[0]
            profile_hash = digest(profile)
            keep = install / "keep-me.txt"
            keep.write_text("Unrelated user file: retain on uninstall.\n")
            run([wine, args.installer.resolve(), "/S", r"/D=C:\FlowBridgeMustNotMove"])
            verify_payload()
            assert not alternate.exists(), "Upgrade moved to a different requested directory"
            assert install_win.lower() in query(settings_key).lower()
            assert keep.is_file() and digest(profile) == profile_hash
            passed("Upgrade stays in registered directory despite different /D; profile and unrelated file preserved")
            # Use the installed Windows path. A Z: Unix-path alias changes the
            # NSIS self-copy launch context under Wine and is not a normal
            # Windows uninstall invocation.
            run([wine, install_win + r"\Uninstall.exe", "/S"])
            wait_until(lambda: not (install / "FlowBridge.exe").exists() and not (install / "Uninstall.exe").exists(), "uninstaller completion")
            for entry in manifest["payload"]:
                assert not (install / entry["path"]).exists(), f"Uninstaller left known payload: {entry['path']}"
            assert not query(uninstall_key), "Uninstall registration remains"
            assert "InstallDir" not in query(settings_key), "InstallDir registration remains"
            assert not any(path.exists() for path in shortcuts), "Start menu shortcuts remain"
            assert keep.read_text() == "Unrelated user file: retain on uninstall.\n"
            assert digest(profile) == profile_hash, "Uninstall changed or removed GUI profile"
            passed("Actual uninstall removes payload, shortcuts and registration; unrelated file and GUI profile retained", retained_profile=str(profile), profile_sha256=profile_hash)
            results["passed"] = True
        except Exception as error:
            results["error"] = str(error)
            note(traceback.format_exc())
            raise
        finally:
            results_path.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
