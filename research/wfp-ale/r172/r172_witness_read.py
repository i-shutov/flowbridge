#!/usr/bin/env python3
"""Read-only, stdlib-only source-pinned negative model. No WFP, IOCTL or driver."""
from __future__ import annotations
import hashlib
import itertools
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
if (ROOT / 'kernel-r19/kernel/src/lib.rs').exists():
    LIB_PATH = ROOT / 'kernel-r19/kernel/src/lib.rs'
    WRAPPER_PATH = ROOT / 'kernel-r19/kernel/wrapper.h'
else:
    LIB_PATH = ROOT / 'snapshot/lib.rs'
    WRAPPER_PATH = ROOT / 'snapshot/wrapper.h'
LIB_SHA = '53f5ce6faa0f9f591974287f38ea890cafeb0dd2'
WRAPPER_SHA = '3fc86a6cc03528c1384954490b796bd97f34338c'
LEDGER_REMOTE_SHA = 'b88c4c9237c4c118517978fc454f5048f522aa7f'


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition: raise AssertionError(message)


def source_gate(lib: str | None = None, wrapper: str | None = None, check_pin: bool = True) -> None:
    lb = LIB_PATH.read_bytes()
    wb = WRAPPER_PATH.read_bytes()
    if check_pin:
        require(git_blob_sha(lb) == LIB_SHA, 'lib.rs exact Git blob mismatch')
        require(git_blob_sha(wb) == WRAPPER_SHA, 'wrapper.h exact Git blob mismatch')
    lib = lb.decode() if lib is None else lib
    wrapper = wb.decode() if wrapper is None else wrapper
    require('D:P(A;;GRGW;;;SY)(A;;GRGW;;;BA)' in lib, 'device SDDL changed')
    require(bool(re.search(r'FB_WITNESS_IOCTL\s*=\s*CTL_CODE\(FILE_DEVICE_UNKNOWN,\s*0x900,\s*METHOD_BUFFERED,\s*FILE_READ_DATA\)', wrapper)), 'witness access changed')
    dispatch = lib.split('unsafe extern "C" fn dispatch(', 1)[1].split('unsafe fn cleanup()', 1)[0]
    require('redirect::ioctl(code,input,k::IoGetRequestorProcess(irp))' in dispatch, 'control IOCTL expected caller validation')
    witness = dispatch.split('if code!=k::FB_WITNESS_IOCTL as u32', 1)[1]
    require('(*STATE.0.get()).pop()' in witness, 'destructive dequeue no longer found')
    # Gate intentionally fails when user/process/object authorization is newly added.
    forbidden = ('IoGetRequestorProcess(', 'ObReferenceObjectByHandle(',
                 'WdmlibIoValidateDeviceIoControlAccess(', 'authorize_witness_reader(',
                 'validate_witness_caller(', 'requestor_process')
    require(not any(t in witness for t in forbidden), 'new witness reader authorization needs re-review')


def trace(producer: bool, live: bool, lost: bool, family: int, epoch: int,
          tuple_reused: bool, order: tuple[str, str]) -> dict:
    # Additional dimensions are model labels, not inputs to kernel read access.
    queue = 1 if producer else 0
    results = []
    for who in order:
        if who == 'standard':
            results.append('ACCESS_DENIED')  # modeled device DACL
        elif lost:
            results.append('NOT_READY')
        elif queue == 0:
            results.append('EMPTY')
        else:
            queue -= 1  # Ledger::pop removes BEFORE owner-live check
            results.append('SUCCESS' if live else 'NOT_READY')
    return dict(producer=int(producer),live=int(live),lost=int(lost),family=family,
                epoch=epoch,tuple_reused=int(tuple_reused),order='/'.join(order),
                outcomes='/'.join(results),queue=queue)


ORDERS = [
    ('broker','admin_other'), ('admin_other','broker'),
    ('standard','broker'), ('broker','standard'),
    ('admin_other','admin_other'), ('broker','broker'),
]


def matrix():
    for producer, live, lost, family, epoch, reused, order in itertools.product(
            (False,True),(False,True),(False,True),(4,6),(1,2),(False,True),ORDERS):
        yield trace(producer,live,lost,family,epoch,reused,order)


class NegativeTests(unittest.TestCase):
    def test_exact_source_gate(self): source_gate()
    def test_source_gate_detects_witness_authorizer(self):
        original=LIB_PATH.read_text()
        patched=original.replace('let result={let _lock=Guard::take();(*STATE.0.get()).pop()};',
                                  'let _reader=IoGetRequestorProcess(irp); let result={let _lock=Guard::take();(*STATE.0.get()).pop()};')
        with self.assertRaises(AssertionError):source_gate(lib=patched,check_pin=False)
    def test_source_gate_detects_witness_pop_replacement(self):
        original=LIB_PATH.read_text()
        with self.assertRaises(AssertionError):source_gate(lib=original.replace('(*STATE.0.get()).pop()', '(*STATE.0.get()).peek()'),check_pin=False)
    def test_no_producer_real_r19_always_no_witness(self):
        for row in matrix():
            if not row['producer']:self.assertNotIn('SUCCESS',row['outcomes'])
    def test_other_admin_can_drain_conditional_witness(self):
        row=trace(True,True,False,4,1,False,('admin_other','broker'))
        self.assertEqual(row['outcomes'],'SUCCESS/EMPTY')
    def test_broker_first_normal(self):
        self.assertEqual(trace(True,True,False,6,1,True,('broker','admin_other'))['outcomes'],'SUCCESS/EMPTY')
    def test_standard_reader_cannot_drain(self):
        self.assertEqual(trace(True,True,False,4,2,False,('standard','broker'))['outcomes'],'ACCESS_DENIED/SUCCESS')
    def test_dead_owner_record_is_consumed(self):
        self.assertEqual(trace(True,False,False,4,1,False,('admin_other','broker'))['outcomes'],'NOT_READY/EMPTY')
    def test_lost_ledger_does_not_return_witness(self):
        self.assertEqual(trace(True,True,True,6,2,True,('admin_other','broker'))['outcomes'],'NOT_READY/NOT_READY')
    def test_family_epoch_tuple_do_not_authorize_reader(self):
        patterns={trace(True,True,False,f,e,t,('admin_other','broker'))['outcomes']
            for f,e,t in itertools.product((4,6),(1,2),(False,True))}
        self.assertEqual(patterns,{'SUCCESS/EMPTY'})


if __name__=='__main__':
    import sys
    if len(sys.argv)>1 and sys.argv[1]=='--matrix':
        source_gate()
        for obj in matrix():print(json.dumps(obj,sort_keys=True,separators=(',',':')))
    else:
        unittest.main()
