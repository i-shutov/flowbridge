#!/usr/bin/env python3
"""Install/upgrade/uninstall the protected native-beta candidate on disposable CI.
This does not load or approve a kernel driver and never modifies boot policy.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, timeout=180):
    print('RUN', args, flush=True)
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    output = result.stdout.decode('utf-8', errors='replace') + result.stderr.decode('utf-8', errors='replace')
    print(output, flush=True)
    require(result.returncode == 0, f'Command failed ({result.returncode}): {output}')
    return output


def wait(predicate, reason):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise RuntimeError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installer', required=True, type=Path)
    parser.add_argument('--harness', required=True, type=Path)
    parser.add_argument('--payload', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(sys.platform == 'win32' and os.environ.get('GITHUB_ACTIONS') == 'true', 'Disposable Windows runner required')
    require(ctypes.windll.shell32.IsUserAnAdmin() != 0, 'Elevated disposable runner required')
    import winreg
    install = Path(os.environ['ProgramW6432'])/'FlowBridgeBeta'
    require(not install.exists(), 'Refusing to change an existing native-beta installation')
    key = r'Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridgeNativeBeta'
    def registered():
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as handle:
                return winreg.QueryValueEx(handle, 'InstallLocation')[0]
        except FileNotFoundError:
            return None
    require(registered() is None, 'Existing native-beta registration')
    args.output.mkdir(parents=True, exist_ok=True)
    report = {'passed': False, 'installer_sha256': digest(args.installer), 'checks': [],
              'driver_loaded': False, 'native_capture_acceptance': False}
    files = ['FlowBridge.exe', 'FlowBridgeCapture.exe', 'flowbridge_ffi.dll', 'flowbridge-cli.exe',
             'dns_policy.ps1', 'resources/presets.json', 'LICENSE', 'README.txt',
             'licenses/nlohmann-json-LICENSE.MIT', 'licenses/THIRD_PARTY_NOTICES.txt']
    try:
        run([str(args.installer.resolve()), '/S'])
        wait(lambda: (install/'Uninstall.exe').is_file(), 'Install did not complete')
        require(Path(registered()) == install, 'Protected install location not registered')
        for file in files:
            require((install/file).is_file() and digest(install/file) == digest(args.payload/file), 'Payload mismatch: '+file)
        report['checks'].append('Protected Program Files installation contains the exact GUI, helper, DLL, DNS policy and resources')
        text = run([str(args.harness.resolve()), str(install/'FlowBridge.exe'), str((args.output/'installed-native-ui.bmp').resolve())])
        require('PASS Win32 GUI' in text and 'PASS Windows DLL' in text, 'Installed GUI/DLL smoke incomplete')
        report['checks'].append('Installed GUI and DLL pass actual TCP/half-close/Start/Stop smoke')
        profile = Path(os.environ['LOCALAPPDATA'])/'FlowBridge/profile.json'
        before = digest(profile)
        keep = install/'user-owned-note.txt'; keep.write_text('preserve this file', encoding='utf-8')
        run([str(args.installer.resolve()), '/S'])
        require(digest(profile) == before and keep.is_file(), 'Upgrade changed user data')
        report['checks'].append('Upgrade preserves user profile and unrelated files')
        run([str(install/'Uninstall.exe'), '/S'])
        wait(lambda: not (install/'FlowBridge.exe').exists() and not (install/'Uninstall.exe').exists(), 'Uninstall incomplete')
        require(all(not (install/file).exists() for file in files), 'Known payload remains')
        require(registered() is None, 'Uninstall registration remains')
        require(digest(profile) == before and keep.read_text(encoding='utf-8') == 'preserve this file', 'Uninstaller removed user data')
        report['checks'].append('Uninstall removes only known payload/registration and preserves user data')
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        (args.output/'native-beta-installer.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print(json.dumps(report, indent=2), flush=True)

if __name__ == '__main__':
    main()
