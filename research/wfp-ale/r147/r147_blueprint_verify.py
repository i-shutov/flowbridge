#!/usr/bin/env python3
"""Bounded offline verifier for R143 design artifacts, not a WFP authorization.

Exit 0: every input is a structurally valid NON-INSTALLABLE design.
Exit 2: at least one rejection, missing input, resource limit or I/O error.
JSONL mode is intended for independent black-box regression campaigns.
No sockets, Windows APIs, driver loading or WFP object operations are used.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys
from typing import BinaryIO

SOURCE = Path(__file__).resolve().parent.parent / 'r143' / 'r143_policy_compiler.py'
spec = importlib.util.spec_from_file_location('r143_offline_compiler', SOURCE)
compiler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compiler)
MAX_DOCUMENT = 65536
MAX_RECORDS = 4096
MAX_TOTAL = 16 * 1024 * 1024


def verdict(raw: bytes, record: int) -> dict:
    code = 'VALID_DESIGN_ONLY'
    try:
        value = compiler.strict_load(raw)
        compiler.validate_blueprint(value)
    except compiler.GateError as exc:
        # GateError contains a stable developer-defined reason, not the input.
        code = 'REJECT:' + str(exc).split(':', 1)[0]
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        code = 'REJECT:INVALID_OR_UNREADABLE_DESIGN'
    valid = code == 'VALID_DESIGN_ONLY'
    return {'record': record, 'code': code, 'design_valid': valid,
            'native_wfp_executed': False, 'release_accepted': False,
            'no_direct_proved': False}


def rejection(record: int, code: str) -> dict:
    return {'record': record, 'code': 'REJECT:' + code, 'design_valid': False,
            'native_wfp_executed': False, 'release_accepted': False,
            'no_direct_proved': False}


def verify_stream(stream: BinaryIO, jsonl: bool = False):
    if not jsonl:
        yield verdict(stream.read(MAX_DOCUMENT + 1), 0)
        return
    total = 0
    for record in range(MAX_RECORDS + 1):
        raw = stream.readline(MAX_DOCUMENT + 1)
        if not raw:
            if record == 0:
                yield rejection(0, 'EMPTY_STREAM')
            return
        total += len(raw)
        if record == MAX_RECORDS:
            yield rejection(record, 'RECORD_LIMIT')
            return
        if total > MAX_TOTAL:
            yield rejection(record, 'TOTAL_LIMIT')
            return
        if len(raw) > MAX_DOCUMENT:
            yield rejection(record, 'DOCUMENT_LIMIT')
            return
        yield verdict(raw, record)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='UTF-8 JSON/JSONL path or - for stdin')
    parser.add_argument('--jsonl', action='store_true')
    args = parser.parse_args(argv)
    accepted = rejected = 0
    stream = None
    try:
        stream = sys.stdin.buffer if args.input == '-' else Path(args.input).open('rb')
        for result in verify_stream(stream, args.jsonl):
            print(json.dumps(result, sort_keys=True, allow_nan=False))
            accepted += int(result['design_valid'])
            rejected += int(not result['design_valid'])
    except OSError:
        print(json.dumps(rejection(accepted + rejected, 'INPUT_IO_ERROR'), sort_keys=True))
        rejected += 1
    finally:
        if stream is not None and stream is not sys.stdin.buffer:
            stream.close()
    print(json.dumps({'summary': True, 'records': accepted + rejected,
                      'accepted_designs': accepted, 'rejected': rejected,
                      'native_wfp_executed': False, 'release_accepted': False,
                      'no_direct_proved': False}, sort_keys=True))
    return 2 if rejected else 0


if __name__ == '__main__':
    raise SystemExit(main())
