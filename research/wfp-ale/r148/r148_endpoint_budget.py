#!/usr/bin/env python3
"""R148: offline negative tests of the R19 Book endpoint/tombstone limits.
No WFP, sockets, process operations, drivers, or networking. This is a model.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

CAP = 32
TOMBSTONES = 4096
TTL = 100_000_000
PIN = 'e1d17217db50362ba9c4efc83af820b6beb094cf'
MARKERS = (
    'pub const CAP: usize = 32;',
    'pub const MAX_ENDPOINT_TOMBSTONES: usize = 4096;',
    'if self.seen_endpoints[..self.seen_count].contains(&origin.endpoint){self.lost=true;return None;}',
    'if self.seen_count==MAX_ENDPOINT_TOMBSTONES{self.lost=true;return None;}',
    'let Some(index)=self.slots.iter().position(|s|!s.live) else{return None;};',
    'self.seen_count+=1;',
    'pub fn kill(&mut self) {self.lost=true;',
)


def source_gate(path: Path) -> None:
    raw = path.read_bytes()
    got = hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()
    if got != PIN:
        raise RuntimeError('SOURCE_GIT_BLOB_MISMATCH:' + got)
    for marker in MARKERS:
        if marker.encode('utf-8') not in raw:
            raise RuntimeError('SOURCE_MARKER_MISSING:' + marker)


class Book:
    def __init__(self):
        self.live: dict[int, int] = {}
        self.seen: set[int] = set()
        self.lost = False

    def issue(self, endpoint: int, now: int) -> str:
        if self.lost or now <= 0 or endpoint <= 0:
            return 'DENY'
        self.live = {key: t for key, t in self.live.items() if now - t <= TTL}
        if endpoint in self.seen:
            self.lost = True
            return 'LATCH_REUSED_ENDPOINT'
        if len(self.seen) == TOMBSTONES:
            self.lost = True
            return 'LATCH_TOMBSTONE_EXHAUSTED'
        if len(self.live) == CAP:
            return 'BLOCK_LIVE_CAP'
        self.seen.add(endpoint)
        self.live[endpoint] = now
        return 'ISSUED'

    def retire(self, endpoint: int) -> None:
        self.live.pop(endpoint, None)

    def kill(self) -> None:
        self.lost = True
        self.live.clear()


def require(ok: bool, stage: str) -> None:
    if type(ok) is not bool or not ok:
        raise RuntimeError("MODEL_INVARIANT_FAILED:" + stage)


def campaign() -> tuple[list[str], dict]:
    rows: list[str] = []
    def record(label: str, result: str, book: Book):
        rows.append(f'{label}|{result}|{len(book.live)}|{len(book.seen)}|{int(book.lost)}\n')
    b = Book()
    for endpoint in range(1, CAP + 2):
        record('burst_' + str(endpoint), b.issue(endpoint, 1), b)
    require(len(b.seen) == CAP and not b.lost, "live-cap-mutation")
    require(rows[-1].split('|')[1] == 'BLOCK_LIVE_CAP', '33rd-connection-must-block')
    b.retire(1)
    record('reclaim_slot', b.issue(CAP + 2, 2), b)
    require(len(b.seen) == CAP + 1, "slot-reclaim")

    b = Book()
    for endpoint in range(1, TOMBSTONES + 2):
        status = b.issue(endpoint, endpoint)
        record('sequential_' + str(endpoint), status, b)
        if status == 'ISSUED':
            b.retire(endpoint)
    require(len(b.seen) == TOMBSTONES and b.lost, "tombstone-budget-exhaustion")
    record('after_budget_loss', b.issue(TOMBSTONES + 2, TOMBSTONES + 2), b)

    b = Book()
    record('original', b.issue(17, 1), b)
    b.retire(17)
    record('reuse_same_endpoint', b.issue(17, 2), b)
    record('fresh_after_reuse', b.issue(18, 3), b)
    require(b.lost, "reused-endpoint-latches")

    b = Book()
    for endpoint in range(1, CAP + 1):
        b.issue(endpoint, 1)
    record('ttl_reclaim', b.issue(CAP + 1, TTL + 2), b)
    require(len(b.live) == 1 and len(b.seen) == CAP + 1, "ttl-reclaims-live-not-seen")

    b = Book()
    b.issue(1, 1)
    b.kill()
    record('killed', b.issue(2, 3), b)
    require(b.lost, "reused-endpoint-latches")
    counts = {kind: sum('|' + kind + '|' in row for row in rows) for kind in
              ['ISSUED', 'BLOCK_LIVE_CAP', 'LATCH_REUSED_ENDPOINT', 'LATCH_TOMBSTONE_EXHAUSTED', 'DENY']}
    return rows, counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--model-only', action='store_true')
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent.parent / 'kernel-r19/kernel/src/handoff.rs')
    args = parser.parse_args()
    if not args.model_only:
        source_gate(args.source)
    rows, counts = campaign()
    print(json.dumps({'model_cases': len(rows), 'counts': counts,
                      'matrix_sha256': hashlib.sha256(''.join(rows).encode('ascii')).hexdigest(),
                      'source_pinned': not args.model_only,
                      'native_windows_executed': False, 'release_accepted': False,
                      'no_direct_proved': False}, sort_keys=True))


if __name__ == '__main__':
    main()
