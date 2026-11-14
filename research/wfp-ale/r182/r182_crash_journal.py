"""R182 user-mode process-crash exercise with real fsync'd file bytes.

No kernel driver, WFP callout, network operation or system setting access.
Models persist-before-ACK and fail-closed recovery only; not power-loss durability.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

OLD_SESSION = 'broker-session-5'
NEW_SESSION = 'broker-session-6'
TXID = 'kernel-tx-1'  # Hypothetical kernel-issued ID; not a Windows API output.
RECORDS = {
    'grant': dict(tx=TXID, event='grant', session=OLD_SESSION, token='flow-opaque-1', tuple='fixed-five-tuple'),
    'ack': dict(tx=TXID, event='ack', session=OLD_SESSION),
    'claim': dict(tx=TXID, event='claim', session=OLD_SESSION),
    'revoke': dict(tx=TXID, event='revoke', session=OLD_SESSION),
}


def encoded(entry):
    data = json.dumps(entry, sort_keys=True, separators=(',', ':')).encode()
    return struct.pack('<II', len(data), zlib.crc32(data)) + data


def worker(filename, scenario):
    stages = {
        'pre_ack': ('grant',),
        'post_claim': ('grant', 'ack', 'claim'),
        'unobserved_revoke': ('grant', 'ack', 'claim'),
        'durable_revoke': ('grant', 'ack', 'claim', 'revoke'),
        'duplicate': ('grant', 'ack', 'claim', 'grant'),
        'conflicting_duplicate': ('grant', 'ack', 'claim', 'conflict'),
    }[scenario]
    volatile_state = {'revoked': False}
    with open(filename, 'wb', buffering=0) as f:
        for stage in stages:
            rec = dict(RECORDS['grant'], token='forged-other-flow') if stage == 'conflict' else RECORDS[stage]
            f.write(encoded(rec))
            f.flush()
            os.fsync(f.fileno())
        if scenario == 'unobserved_revoke':
            volatile_state['revoked'] = True  # Model a real in-process revoke event.
            assert volatile_state['revoked']  # Never written to the journal.
        # Deliberately exit without Python cleanup. Volatile revocation is not journalled.
        os._exit(61)


def recover(filename, current_session):
    data = Path(filename).read_bytes()
    pos, entries, first = 0, set(), {}
    while pos < len(data):
        if len(data) - pos < 8:
            return dict(valid=False, reason='partial_header', strict=False, naive=False)
        n, checksum = struct.unpack_from('<II', data, pos)
        pos += 8
        if n == 0 or n > 2048 or n > len(data) - pos:
            return dict(valid=False, reason='invalid_length', strict=False, naive=False)
        payload = data[pos:pos+n]
        pos += n
        if zlib.crc32(payload) != checksum:
            return dict(valid=False, reason='bad_crc', strict=False, naive=False)
        try:
            e = json.loads(payload)
        except (UnicodeDecodeError, ValueError):
            return dict(valid=False, reason='invalid_json', strict=False, naive=False)
        if e.get('tx') != TXID or e.get('session') != OLD_SESSION:
            return dict(valid=False, reason='foreign_transaction', strict=False, naive=False)
        kind=e.get('event')
        if kind not in RECORDS:
            return dict(valid=False, reason='invalid_event', strict=False, naive=False)
        if kind in first and first[kind] != e:
            return dict(valid=False, reason='conflicting_duplicate', strict=False, naive=False)
        first[kind] = e
        entries.add(kind)
    complete={'grant','ack','claim'}.issubset(entries)
    revoke='revoke' in entries
    strict=complete and not revoke and current_session==OLD_SESSION
    naive='grant' in entries and not revoke
    return dict(valid=True, reason='ok', strict=strict, naive=naive, events=sorted(entries))


def run():
    results=[]
    with tempfile.TemporaryDirectory(prefix='flowbridge-r182-') as td:
        for name in ('pre_ack','post_claim','unobserved_revoke','durable_revoke','duplicate','conflicting_duplicate'):
            path=Path(td)/f'{name}.journal'
            run=subprocess.run([sys.executable, __file__, 'worker', str(path), name],
                               capture_output=True, check=False)
            assert run.returncode==61 and path.is_file(), (name, run.returncode, run.stderr)
            snapshot=path.read_bytes()
            outcome=recover(path, NEW_SESSION)
            results.append(dict(scenario=name, sha256=hashlib.sha256(snapshot).hexdigest(),
                                length=len(snapshot), **outcome))
        # The journal cannot distinguish clean process termination from lost volatile revocation.
        assert results[1]['sha256']==results[2]['sha256']
        assert results[1]['naive'] and results[2]['naive']
        assert all(not x['strict'] for x in results)
        assert results[4]['valid'] and not results[5]['valid']
        assert results[3]['events'][-1]=='revoke'
        # Byte-level truncation of an otherwise fsync'd grant must fail closed.
        src=Path(td)/'post_claim.journal'
        torn=Path(td)/'truncated.journal'
        torn.write_bytes(src.read_bytes()[:-2])
        failed=recover(torn,NEW_SESSION)
        assert not failed['valid'] and not failed['strict']
        results.append(dict(scenario='truncated', **failed))
    return results

if __name__=='__main__':
    if len(sys.argv)>=2 and sys.argv[1]=='worker':
        worker(sys.argv[2],sys.argv[3])
    else:
        for result in run(): print(json.dumps(result, sort_keys=True, separators=(',',':')))
