#!/usr/bin/env python3
"""R173 deterministic, offline negative WITNESS-queue contract (not WFP runtime)."""
import argparse
import hashlib
import itertools
import json
import pathlib
import re
import unittest

CAP = 32
PINNED = {
    'kernel/src/ledger.rs': 'b88c4c9237c4c118517978fc454f5048f522aa7f',
    'kernel/src/lib.rs': '53f5ce6faa0f9f591974287f38ea890cafeb0dd2',
    'kernel/wrapper.h': '3fc86a6cc03528c1384954490b796bd97f34338c',
    'broker_windows.rs': '329ef14b63e70226bfad7372b0014559213abd04',
    'broker.rs': '6163e84aea08ddde7e51a7fb94ccb6d68ae951fb',
    'broker_lifecycle.rs': '211b5e5cee03f4d8ea13fc23e1be0777cbfa09c1',
    'trusted-ssh-r37/src/lib.rs': 'c6d8c8746fac45073c11557de893164e49d830eb',
}

def git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def source_gate(repo_root: pathlib.Path) -> dict:
    root = repo_root / 'research' / 'wfp-ale' / 'kernel-r19'
    sources = {}
    for name, expected in PINNED.items():
        data = (root / name).read_bytes()
        got = git_blob_sha(data)
        if got != expected:
            raise ValueError(f'source mismatch {name}: {got}, expected {expected}')
        sources[name] = data.decode('utf-8')
    ledger = sources['kernel/src/ledger.rs']
    lib = sources['kernel/src/lib.rs']
    bw = sources['broker_windows.rs']
    broker = sources['broker.rs']
    required = [
        ('queue capacity', 'pub const MAX_RECORDS: usize = 32;', ledger),
        ('queue full latches', 'if self.count==MAX_RECORDS || self.receipt==u64::MAX {self.lost=true;return Err(Denied::Full);}', ledger),
        ('producer writes queue', 'self.count+=1;Ok(())', ledger),
        ('destructive pop', 'self.count-=1;', ledger),
        ('kernel read dispatch', '(*STATE.0.get()).pop()', lib),
        ('broker ioctl whitelist', 'matches!(code,h::ARM|h::CLAIM|h::PING|h::STOP)', bw),
        ('broker ioctl call', 'DeviceIoControl(self.0.as_raw_handle(),code,', bw),
        ('broker opens device', 'Device::open()', broker),
        ('broker heartbeat', 'd.command(handoff::PING,&[])', broker),
    ]
    for label, term, s in required:
        if term not in s: raise ValueError('source-shape mismatch: ' + label)
    # The compiled user-mode source closure follows broker.rs mod declarations and
    # the direct trusted-ssh dependency; include every Rust source in these directories.
    usermode = [p for p in root.glob('*.rs') if p.name != 'kernel.rs'] + list((root / 'trusted-ssh-r37/src').glob('*.rs'))
    other_mentions = []
    for file in usermode:
        src = file.read_text('utf-8')
        # WITNESS is allowed only in comments/docs, never in actual Rust identifiers
        # or a DeviceIoControl WITNESS call. Reject pending interface changes.
        code = '\n'.join(line.split('//')[0] for line in src.splitlines())
        if re.search(r'WITNESS_IOCTL|FB_WITNESS|\b0x226400\b', code, re.I): other_mentions.append(str(file.relative_to(root)))
    if other_mentions: raise ValueError('user-mode witness call detected: ' + repr(other_mentions))
    # Only broker_windows.rs may call DeviceIoControl in the compiled broker tree.
    calls = []
    for file in usermode:
        code = '\n'.join(line.split('//')[0] for line in file.read_text('utf-8').splitlines())
        n = len(re.findall(r'\bDeviceIoControl\s*\(', code))
        if n: calls.append((str(file.relative_to(root)), n))
    if calls != [('broker_windows.rs',2)]:
        raise ValueError('DeviceIoControl invocation surface changed: ' + repr(calls))
    return {'pinned_blobs': PINNED, 'brokermode_rust_files': sorted(str(p.relative_to(root)) for p in usermode), 'device_ioctl_decl_plus_call': calls}

def simulate(producer: bool, reader: str, events: int) -> dict:
    # One valid selected process, fixed session, family and canonical appId:
    # every observe succeeds until a *33rd* undrained record is attempted.
    count = 0
    lost = False
    successes = 0
    reads = 0
    for _ in range(events):
        if producer and not lost:
            if count == CAP: lost = True
            else: count += 1; successes += 1
        if reader == 'each' and producer and not lost and count:
            count -= 1; reads += 1
    if reader == 'late' and producer and not lost and count:
        count -= 1; reads += 1
    # ready() checks Ledger::lookup(), returning None when lost, then kill().
    book_killed_on_next_ready = lost
    return {'enqueued':successes,'queued':count,'consumed':reads,'ledger_lost':lost,
            'next_ready_kills_book':book_killed_on_next_ready}

def cases():
    for family, producer, reader, n in itertools.product((4,6),(False,True),('none','each','late'),(0,1,31,32,33,34,40)):
        yield {'family':family,'producer':producer,'reader':reader,'events':n,**simulate(producer,reader,n)}

def matrix():
    for case in cases():
        print(json.dumps(case, sort_keys=True, separators=(',',':')))

class ContractTests(unittest.TestCase):
    def test_current_no_producer_never_success(self):
        for n in (0,1,31,32,33,40,1000):
            x=simulate(False,'none',n); self.assertEqual(x['enqueued'],0);self.assertFalse(x['ledger_lost'])
    def test_counterfactual_32nd_fits(self):
        x=simulate(True,'none',32);self.assertEqual((x['enqueued'],x['queued']), (32,32));self.assertFalse(x['ledger_lost'])
    def test_counterfactual_33rd_poison(self):
        x=simulate(True,'none',33);self.assertEqual((x['enqueued'],x['queued']), (32,32));self.assertTrue(x['ledger_lost']);self.assertTrue(x['next_ready_kills_book'])
    def test_late_reader_cannot_rescue_overflow(self):
        self.assertTrue(simulate(True,'late',33)['ledger_lost']);self.assertEqual(simulate(True,'late',33)['consumed'],0)
    def test_hypothetical_continuous_reader_prevents_queue_full(self):
        x=simulate(True,'each',40);self.assertEqual(x['enqueued'],40);self.assertEqual(x['consumed'],40);self.assertFalse(x['ledger_lost'])
    def test_after_32_late_read_avoids_full_so_far(self):
        x=simulate(True,'late',32);self.assertEqual(x['queued'],31);self.assertEqual(x['consumed'],1);self.assertFalse(x['ledger_lost'])
    def test_broker_lacks_reader_in_current_code(self):
        # Model does not assert actual runtime event count or kernel execution.
        self.assertTrue(simulate(True,'none',33)['next_ready_kills_book'])
    def test_different_family_is_not_a_queue_key(self):
        a=list(cases());self.assertEqual(len(a),84)
        self.assertEqual([x['queued'] for x in a[:42]],[x['queued'] for x in a[42:]])

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--matrix',action='store_true')
    parser.add_argument('-q','--quiet',action='store_true')
    parser.add_argument('--source-gate',type=pathlib.Path)
    args=parser.parse_args()
    if args.source_gate is not None: print(json.dumps(source_gate(args.source_gate),sort_keys=True))
    elif args.matrix: matrix()
    else: unittest.main(argv=[__file__],verbosity=1 if args.quiet else 2)
