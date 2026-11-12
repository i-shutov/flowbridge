#!/usr/bin/env python3
"""R149: deterministic negative tests for R19 global process ledger exhaustion.
No OS calls; no driver, sockets, network or filtering. Exact-checkout source pin
is mandatory unless the weaker --model-only option is explicitly requested.
"""
import argparse
import hashlib
import json
from pathlib import Path

CAP = 256
PINS = {
    'ledger.rs': ('b88c4c9237c4c118517978fc454f5048f522aa7f', (
        'pub const MAX_OWNERS: usize = 256;',
        'if self.used==MAX_OWNERS { self.lost=true; return Err(Denied::Full); }',
        'if let Some(existing) = self.owners[..self.used].iter_mut().find(|o|o.pid==owner.pid)',
        'existing.live=false; self.lost=true; return Err(Denied::ReusedPid);',
        'owner.live=false;', 'self.owners[self.used]=owner; self.used+=1; Ok(())',
        'if self.lost {return None;}')),
    'lib.rs': ('53f5ce6faa0f9f591974287f38ea890cafeb0dd2', (
        'unsafe extern "C" fn process_event(',
        '(*STATE.0.get()).died(id,process as usize)',
        '(*STATE.0.get()).born(owner).is_ok()',
        'k::ObfReferenceObject(process.cast());k::ObfReferenceObject(c.FileObject.cast());')),
}

def source_gate(root: Path):
    for filename, (expected, markers) in PINS.items():
        data = (root / filename).read_bytes()
        digest = hashlib.sha1(b'blob '+str(len(data)).encode('ascii')+b'\0'+data).hexdigest()
        if digest != expected or any(m.encode() not in data for m in markers):
            raise RuntimeError('SOURCE_GATE_FAIL:'+filename+':'+digest)

class Ledger:
    def __init__(self):
        self.owners = {}
        self.used = 0
        self.lost = False
    def born(self, pid, eligible=True):
        # Ineligible metadata rejected in process_event BEFORE Ledger::born.
        if not eligible: return 'SKIPPED_INELIGIBLE'
        if self.lost: return 'DENIED_LOST'
        if pid in self.owners:
            self.owners[pid] = False
            self.lost = True
            return 'LATCH_PID_REUSE'
        if self.used == CAP:
            self.lost = True
            return 'LATCH_OWNER_LIMIT'
        self.owners[pid] = True
        self.used += 1
        return 'BORN'
    def died(self, pid):
        if pid in self.owners: self.owners[pid] = False
        return 'DIED'
    def lookup(self, pid):
        return 'LOOKUP_OK' if not self.lost and self.owners.get(pid, False) else 'LOOKUP_DENIED'

def require(value: bool, label: str):
    if type(value) is not bool or not value:
        raise RuntimeError("NEGATIVE_INVARIANT_FAILED:" + label)

def campaign():
    rows = []
    def capture(label, op, ledger):
        rows.append(f'{label}|{op}|{ledger.used}|{int(ledger.lost)}\n')
    b=Ledger()
    capture('selected_alive',b.born(101),b)
    for i in range(1, 256):
        pid = 1000 + i
        capture('unrelated_birth_'+str(i),b.born(pid),b)
        capture('unrelated_exit_'+str(i),b.died(pid),b)
    capture('selected_before_257',b.lookup(101),b)
    capture('unrelated_257',b.born(1256),b)
    capture('selected_after_257',b.lookup(101),b)
    capture('even_new_selected_denied',b.born(102),b)
    require((b.used,b.lost)==(256,True), "256-257-limit")
    c=Ledger()
    capture('reuse_selected',c.born(201),c)
    capture('reuse_unrelated_first',c.born(222),c)
    capture('reuse_unrelated_exit',c.died(222),c)
    capture('reuse_unrelated_second',c.born(222),c)
    capture('selected_after_unrelated_reuse',c.lookup(201),c)
    require((c.used,c.lost)==(2,True), "unrelated-pid-reuse")
    d=Ledger()
    for i in range(1,260): capture('ineligible_'+str(i),d.born(i,eligible=False),d)
    capture('first_eligible_after_skips',d.born(401),d)
    require((d.used,d.lost)==(1,False), "ineligible-filtering")
    e=Ledger()
    capture('owner_before_early_reuse',e.born(777),e)
    capture('live_pid_collision',e.born(777),e)
    capture('cannot_lookup_collided',e.lookup(777),e)
    require(e.lost, "live-pid-reuse")
    return rows

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--model-only',action='store_true')
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parent.parent/'kernel-r19/kernel/src')
    args=p.parse_args()
    if not args.model_only: source_gate(args.source_root)
    rows=campaign()
    out={"cases":len(rows),"sha256":hashlib.sha256(''.join(rows).encode()).hexdigest(),
         "source_pinned":not args.model_only,"native_wfp_executed":False,
         "release_accepted":False,"no_direct_proved":False}
    print(json.dumps(out,sort_keys=True))

if __name__=='__main__':main()
