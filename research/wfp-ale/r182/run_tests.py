#!/usr/bin/env python3
"""Build and execute the R182 Rust model tests on the actual CI host.

No networking, driver, native Windows configuration or WFP invocation.
Any failure exits nonzero; no ignored, skipped or filtered tests are accepted.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile


def run(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    source = Path(__file__).with_name("retained_authority.rs")
    with tempfile.TemporaryDirectory() as directory:
        exe = Path(directory) / ("r182-tests.exe" if sys.platform=="win32" else "r182-tests")
        try:
            compiler=run(["rustc","--version"]).stdout.strip()
            run(["rustc","--edition=2021","--deny=warnings","--test",str(source),
                 "-o",str(exe)])
            result=run([str(exe),"--test-threads=1","--nocapture"])
        except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as exc:
            print("R182_TESTS_FAILED", file=sys.stderr)
            if isinstance(exc, subprocess.CalledProcessError):
                print((exc.stderr or exc.stdout)[-4500:], file=sys.stderr)
            return 1
    summary=re.search(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored",result.stdout)
    if not summary or int(summary[1])<24 or int(summary[2])!=0 or int(summary[3])!=0:
        print("R182_TEST_COUNTS_NOT_ACCEPTED", file=sys.stderr)
        print(result.stdout[-2500:], file=sys.stderr)
        return 1
    report={"schema":"flowbridge-r182-rust-model-test-v1",
            "host_platform":platform.system(),
            "host_architecture":platform.machine(),
            "rustc":compiler,
            "tests_passed":int(summary[1]),"tests_failed":0,"tests_ignored":0,
            "model_only":True,"kernel_driver_executed":False,
            "wfp_filter_mutated":False,"native_packet_attribution_proved":False,
            "native_reauthorization_proved":False,
            "physical_no_direct_proved":False,"release_1_0_accepted":False}
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,sort_keys=True))
    return 0


if __name__=="__main__":
    sys.exit(main())
