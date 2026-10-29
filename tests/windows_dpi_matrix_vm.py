#!/usr/bin/env python3
"""DPI/work-area evidence from an ACTUAL disposable Windows desktop VM.

Operator must configure the VM display DPI/resolution before each run.
Does not change system DPI, edit the registry, or claim visual legibility.
Run each of 96/120/144/192 on an authorized self-hosted Windows VM.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys


class Rect(ctypes.Structure):
    _fields_ = [('left', ctypes.c_long), ('top', ctypes.c_long),
                ('right', ctypes.c_long), ('bottom', ctypes.c_long)]


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def actual_display():
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    user32.GetSystemMetrics.argtypes = [ctypes.c_int]
    user32.GetSystemMetrics.restype = ctypes.c_int
    # The script's metrics must be physical pixels, not DPI-virtualized
    # coordinates from a DPI-unaware process.
    try:
        user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        user32.SetProcessDpiAwarenessContext.restype = ctypes.c_int
        user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except (AttributeError, OSError):
        user32.SetProcessDPIAware()
    rect = Rect()
    user32.SystemParametersInfoW.argtypes = [
        ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
    require(user32.SystemParametersInfoW(48, 0, ctypes.byref(rect), 0),
            'Cannot read real Windows desktop work area')
    return {'width': user32.GetSystemMetrics(0), 'height': user32.GetSystemMetrics(1),
            'workarea': [rect.left, rect.top, rect.right, rect.bottom]}


def bmp_info(path):
    data = path.read_bytes()
    require(len(data) >= 54 and data[:2] == b'BM',
            'Missing or truncated Windows UI screenshot: ' + path.name)
    width, height = struct.unpack_from('<ii', data, 18)
    require(width >= 920 and height >= 600,
            'Incomplete GUI client screenshot (clipped): ' + path.name)
    return {'name': path.name, 'pixels': [width, abs(height)],
            'sha256': hashlib.sha256(data).hexdigest(),
            'size_bytes': len(data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gui', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--expected-dpi', type=int, choices=(96, 120, 144, 192), required=True)
    parser.add_argument('--expected-resolution', default='1366x768')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'win32' and os.environ.get('FLOWBRIDGE_DPI_VM') == '1',
            'Dedicated operator-authorized Windows VM must set FLOWBRIDGE_DPI_VM=1')
    report = {
        'passed': False, 'commit': os.environ.get('GITHUB_SHA'),
        'platform': platform.platform(),
        'expected_window_dpi': args.expected_dpi,
        'expected_resolution': args.expected_resolution,
        'screenshots': [], 'checks': [],
        'manual_visual_review_complete': False,
        'keyboard_accessibility_review_complete': False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        gui = args.gui.resolve(strict=True)
        harness = args.harness.resolve(strict=True)
        expected = tuple(map(int, args.expected_resolution.split('x', 1)))
        require(len(expected) == 2 and all(i > 0 for i in expected),
                'Expected resolution must be WIDTHxHEIGHT')
        report['display'] = actual_display()
        observed = report['display']
        require((observed['width'], observed['height']) == expected,
                f'Wrong VM monitor resolution: {observed["width"]}x{observed["height"]}; '
                f'operator must configure {expected[0]}x{expected[1]}')
        work = observed['workarea']
        require(work[2] - work[0] >= 980 and work[3] - work[1] >= 680,
                'Real work area cannot hold compact FlowBridge desktop window')
        report['checks'].append('Actual primary desktop resolution and work area verified')

        base = args.output.parent / 'ui.bmp'
        process = subprocess.run([str(harness), str(gui), str(base)],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 timeout=150, text=True, errors='replace')
        report['harness_exit_code'] = process.returncode
        require(process.returncode == 0,
                'Native UI/installer smoke failed; visual review evidence is incomplete')
        found = re.search(r'FB_QA_WINDOW_DPI=(\d+)', process.stdout)
        require(found, 'Native Win32 smoke did not record GetDpiForWindow')
        report['actual_window_dpi'] = int(found.group(1))
        require(report['actual_window_dpi'] == args.expected_dpi,
                'DPI is not configured on this actual VM; automated simulation is not acceptance')
        require('PASS compact Windows GUI:' in process.stdout,
                'Native on-screen window bounds and child layout QA did not execute')
        report['checks'].append('Actual GetDpiForWindow matches configured per-monitor DPI')
        report['checks'].append('Native GUI child/window geometry, networking, Start/Stop and close QA passed')
        names = ('dashboard', 'ssh', 'proxy', 'apps', 'advanced')
        for name in names:
            target = args.output.parent / ('ui-compact-' + name + '.bmp')
            report['screenshots'].append(bmp_info(target))
        require(len({image['sha256'] for image in report['screenshots']}) == len(names),
                'UI pages are duplicates rather than five independently rendered views')
        report['checks'].append('Five distinct full-client BMP screenshots hashed and retained')
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
