#!/usr/bin/env python3
"""R38: compare a dashboard-returned PE to exact unsigned CI source.

Never execute, load, sign or copy a driver. The signature is checked separately
by Windows SignTool under kernel signing policy; this proves section bytes only.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys


class Rejected(ValueError):
    pass


def take(data: bytes, offset: int, length: int) -> bytes:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise Rejected("pe_bounds")
    return data[offset:offset + length]


def number(data: bytes, offset: int, typ: str) -> int:
    size = struct.calcsize(typ)
    return struct.unpack(typ, take(data, offset, size))[0]


def sections(data: bytes) -> dict:
    if take(data, 0, 2) != b"MZ":
        raise Rejected("not_pe_dos")
    peoff = number(data, 60, "<I")
    if take(data, peoff, 4) != b"PE\x00\x00":
        raise Rejected("not_pe_nt")
    if number(data, peoff + 4, "<H") != 0x8664:
        raise Rejected("not_x64")
    n = number(data, peoff + 6, "<H")
    optlen = number(data, peoff + 20, "<H")
    optoff = peoff + 24
    if not 1 <= n <= 32 or optlen < 240 or number(data, optoff, "<H") != 0x20B:
        raise Rejected("invalid_pe_plus")
    if number(data, optoff + 68, "<H") != 1:
        raise Rejected("not_native_subsystem")
    directory = {}
    for i in range(n):
        offset = optoff + optlen + i * 40
        name = take(data, offset, 8).rstrip(b"\x00").decode("ascii")
        rawlen = number(data, offset + 16, "<I")
        rawoff = number(data, offset + 20, "<I")
        flags = number(data, offset + 36, "<I")
        if rawlen == 0 or rawoff == 0 or name in directory:
            raise Rejected("bad_section")
        if flags & 0x20000000 and flags & 0x80000000:
            raise Rejected("writable_executable_section")
        section = take(data, rawoff, rawlen)
        directory[name] = {
            "raw_size": rawlen,
            "raw_sha256": hashlib.sha256(section).hexdigest(),
            "rva": number(data, offset + 12, "<I"),
            "attributes": flags,
        }
    if ".text" not in directory:
        raise Rejected("missing_text")
    return directory


def compare(source: bytes, signed: bytes) -> dict:
    before, after = sections(source), sections(signed)
    if before != after:
        raise Rejected("signed_driver_section_mismatch")
    return {
        "ok": True,
        "section_count": len(before),
        "original_unsigned_sha256": hashlib.sha256(source).hexdigest(),
        "returned_signed_sha256": hashlib.sha256(signed).hexdigest(),
        "all_loadable_section_bytes_equal": True,
        "signature_verified": False,
        "driver_loaded": False,
        "g2_pass": False,
        "release_accepted": False,
    }


def main() -> int:
    from argparse import ArgumentParser
    p = ArgumentParser(description=__doc__)
    p.add_argument("unsigned_sys", type=Path)
    p.add_argument("signed_sys", type=Path)
    args = p.parse_args()
    try:
        result = compare(args.unsigned_sys.read_bytes(), args.signed_sys.read_bytes())
    except (OSError, Rejected, UnicodeError):
        result = {"ok": False, "reason": "pe_section_mismatch_or_invalid", "g2_pass": False}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
