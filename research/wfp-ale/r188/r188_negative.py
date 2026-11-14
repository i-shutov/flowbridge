#!/usr/bin/env python3
"""Offline BFE selected-AppId substitution counterexample; no native WFP or network."""
from hashlib import sha256
from pathlib import Path
import json


def appid(letter: str) -> bytes:
    return ('\\device\\harddiskvolume3\\apps\\' + letter + '.exe').encode('utf-16-le') + b'\0\0'


def evidence():
    a, b = appid('a'), appid('b')
    if not (len(a) == len(b) and a != b and a.endswith(b'\0\0')):
        raise ValueError('fixture not equal-length and distinct')
    h = sha256()
    count = dict(total=0, old_pass=0, strict_pass=0, false_positive=0, false_negative=0)
    for path in (0, 1):
        selected = (a, b)[path]
        other = (b, a)[path]
        for structure in range(16):
            for equality in range(16):
                observed = [selected if equality & (1 << i) else other for i in range(4)]
                # R187 checks correct condition type, available even-length blob and all shapes;
                # the old Rust code DOES NOT check bytes against selected identity.
                old = int(structure == 15 and all(len(x) == len(selected) for x in observed))
                strict = int(structure == 15 and all(x == selected for x in observed))
                count['total'] += 1
                count['old_pass'] += old
                count['strict_pass'] += strict
                count['false_positive'] += old * (1 - strict)
                count['false_negative'] += strict * (1 - old)
                h.update(f'{path},{structure},{equality},{old},{strict}\n'.encode())
    if count != dict(total=512, old_pass=32, strict_pass=2,
                     false_positive=30, false_negative=0):
        raise ValueError('unexpected counterexample totals')
    return count, h.hexdigest()


def audit(source: str) -> bool:
    required = (
        'FwpmGetAppIdFromFileName0(', 'FwpmTransactionBegin0(engine.0, FWPM_TXN_READ_ONLY)',
        'require(actual == selected, "selected_appid_bytes_mismatch")?',
        'fn selected_appid(path: &OsStr)',
        'inspect(engine.0, &selected)', '"selected_appid_utf16_terminator"',
    )
    banned = ('FwpmFilterAdd0(', 'FwpsCalloutRegister', 'FwpmTransactionBegin0(engine.0, 0)',
              'DeviceIoControl(', 'WSAIoctl(', 'std::net::TcpStream')
    return all(token in source for token in required) and not any(token in source for token in banned)


if __name__ == '__main__':
    base = Path(__file__).resolve().parent
    src = (base / 'main.rs').read_text()
    old = (base.parent / 'r187' / 'src' / 'main.rs')
    if not audit(src):
        raise ValueError('R188 source safety/identity check missing')
    if audit(src.replace('require(actual == selected, "selected_appid_bytes_mismatch")?',
                         'require(true, "selected_appid_bytes_mismatch")?')):
        raise ValueError('mutant escaped source gate')
    if old.is_file():
        if 'require(actual == selected,' in old.read_text():
            raise ValueError('historical source unexpectedly repaired')
    n, digest = evidence()
    print(json.dumps(dict(count=n, matrix_sha256=digest, rust_source_gate=True), sort_keys=True))
