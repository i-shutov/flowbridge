#!/usr/bin/env python3
"""Install and launch the local package only on a disposable macOS CI runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import time


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def run(*command):
    print('RUN', command, flush=True)
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=120)
    text = result.stdout.decode('utf-8', errors='replace')
    print(text, flush=True)
    return text


def main():
    require(sys.platform == 'darwin' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_OS') == 'macOS', 'Disposable macOS CI runner required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    packages = list(args.package_dir.glob('*.pkg'))
    require(len(packages) == 1, 'Expected exactly one package')
    package = packages[0].resolve()
    app = Path('/Applications/FlowBridge.app')
    require(not app.exists(), 'Refusing to replace an existing application')
    args.output.mkdir(parents=True, exist_ok=True)
    report = {'commit': os.environ.get('GITHUB_SHA'), 'platform': 'native macOS',
              'package_sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
              'passed': False, 'checks': [], 'signed_installer': False,
              'network_extension_activated': False}

    def passed(message):
        print('PASS', message, flush=True)
        report['checks'].append(message)

    process = None
    try:
        run('/usr/bin/sudo', '/usr/sbin/installer', '-pkg', str(package), '-target', '/')
        binary = app / 'Contents/MacOS/FlowBridge'
        require(binary.is_file(), 'Installer did not install into /Applications')
        info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        require(info['CFBundleIdentifier'] == 'org.flowbridge.FlowBridge', 'Unexpected bundle ID')
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', str(app))
        run('/usr/bin/xcrun', 'lipo', str(binary), '-verify_arch', 'arm64', 'x86_64')
        resources = app / 'Contents/Resources/presets.json'
        require(resources.is_file() and json.loads(resources.read_text()), 'Missing app presets')
        passed('Actual package installation, universal executable, code signature and presets')
        with (args.output / 'application-launch.log').open('wb') as log:
            process = subprocess.Popen([str(binary)], stdout=log, stderr=subprocess.STDOUT)
            time.sleep(4)
            require(process.poll() is None, 'Installed application exited during launch')
            passed('Installed SwiftUI application launches without an immediate crash')
            process.terminate()
            process.wait(timeout=15)
            process = None
        data = Path.home() / 'Library/Application Support/FlowBridge'
        data.mkdir(parents=True, exist_ok=True)
        marker = data / 'ci-preserve-user-data.txt'
        marker.write_text('Preserve user data across upgrade.\n')
        before = {str(p.relative_to(data)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in data.rglob('*') if p.is_file()}
        run('/usr/bin/sudo', '/usr/sbin/installer', '-pkg', str(package), '-target', '/')
        for relative, expected in before.items():
            require(hashlib.sha256((data / relative).read_bytes()).hexdigest() == expected,
                    'Upgrade changed user data: ' + relative)
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', str(app))
        passed('Package upgrade preserves user settings and the installed app signature')
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        (args.output / 'native-macos-result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
