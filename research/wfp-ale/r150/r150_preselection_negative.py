#!/usr/bin/env python3
"""R150: pure offline architecture counterexamples; no system or network access.

Two models: current R19 global, non-evicting owner book and proposed
preselected-only generation-scoped ledger. Proposed design is NOT deployed.
All birth, owner and selected AppId values are synthetic assumed kernel inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path

PIN = {
    'ledger.rs': ('b88c4c9237c4c118517978fc454f5048f522aa7f',
                  ('pub const MAX_OWNERS: usize = 256;', 'if self.used==MAX_OWNERS { self.lost=true; return Err(Denied::Full); }', 'existing.live=false; self.lost=true; return Err(Denied::ReusedPid);')),
    'lib.rs': ('53f5ce6faa0f9f591974287f38ea890cafeb0dd2',
               ('unsafe extern "C" fn process_event(', '(*STATE.0.get()).born(owner).is_ok()', 'k::ObfReferenceObject(process.cast());')),
    'redirect.rs': ('a093f049d162987981a957aac90db1014bc6ff09',
                    ('let owner=(*STATE.0.get()).lookup(r.pid);', 'r.armed=false;r.book.kill();')),
}
SELECTED = 'opaque-appid:fully-qualified-selected'
SIBLING = 'opaque-appid:same-basename-different-path'
FIVE = 'v4|tcp|192.0.2.10:3001|198.51.100.11:443'


def need(ok, message):
    if type(ok) is not bool or not ok:
        raise RuntimeError('INVARIANT:' + message)


def source_gate(path):
    for fname, (expected, markers) in PIN.items():
        raw = (path / fname).read_bytes()
        sha = hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\x00' + raw).hexdigest()
        need(sha == expected and all(m.encode() in raw for m in markers), 'SOURCE_PIN_' + fname)


class R19:
    def __init__(self): self.seen = set(); self.live = set(); self.lost = False
    def birth(self, pid):
        if self.lost: return 'DENY_LOST'
        if pid in self.seen: self.lost = True; return 'LATCH_REUSE'
        if len(self.seen) == 256: self.lost = True; return 'LATCH_FULL'
        self.seen.add(pid); self.live.add(pid); return 'BORN'
    def death(self, pid): self.live.discard(pid); return 'DIED'
    def owner(self, pid): return 'OK' if not self.lost and pid in self.live else 'DENY'


class Candidate:
    """User-mode *specification*, no asserted Windows process authenticity."""
    def __init__(self, capacity=4):
        self.selection = None
        self.live = {}
        self.seq = 0
        self.tickets = {}
        self.capacity = capacity
        self.lost = False
    def configure(self, appid):
        if self.selection is not None or not appid or self.lost: self.lost = True; return 'DENY_CONFIG'
        self.selection = appid
        return 'CONFIGURED'
    def birth(self, pid, epoch, key, ptr, appid):
        if self.lost: return 'DENY_LOST'
        if self.selection is None: return 'IGNORED_UNCONFIGURED'
        if appid != self.selection: return 'IGNORED_OUTSIDE_SCOPE'
        if not all((pid,epoch,key,ptr)): return 'DENY_INVALID'
        if pid in self.live: self.lost = True; return 'LATCH_LIVE_COLLISION'
        if len(self.live) >= self.capacity: return 'DENY_SELECTED_CAP'
        self.seq += 1
        self.live[pid] = (epoch,key,ptr,self.seq)
        return 'TRACK_SELECTED'
    def death(self, pid, ptr):
        if self.lost: return 'DENY_LOST'
        owner = self.live.get(pid)
        if owner is None: return 'IGNORED_EXIT'
        if owner[2] != ptr:
            self.lost = True
            self.tickets.clear()
            return 'LATCH_EXIT_IDENTITY'
        del self.live[pid]
        self.tickets = {k:v for k,v in self.tickets.items() if v[0] != pid}
        return 'RELEASE_REF_AFTER_RETIRE'
    def owner(self, pid, epoch, key, ptr):
        if self.lost: return 'DENY_LOST'
        o = self.live.get(pid)
        return 'OK' if o and o[:3] == (epoch,key,ptr) else 'DENY_NO_KERNEL_BIRTH'
    def issue(self, pid, epoch, key, ptr, endpoint, five):
        if self.owner(pid,epoch,key,ptr) != 'OK': return None
        self.seq += 1
        ticket = self.seq
        self.tickets[ticket] = (pid,epoch,key,ptr,self.live[pid][3],endpoint,five)
        return ticket
    def claim(self, ticket, pid, epoch, key, ptr, endpoint, five):
        remembered = self.tickets.pop(ticket,None)
        if self.lost or remembered is None: return 'REJECT'
        owner = self.live.get(pid)
        actual = (pid,epoch,key,ptr,owner[3] if owner else None,endpoint,five)
        return 'MODEL_ROUTE' if owner and remembered == actual else 'REJECT'


def campaign():
    rows=[]
    def put(label,result,r,c):
        rows.append(f'{label}|{result}|{len(r.seen)}|{int(r.lost)}|{len(c.live)}|{int(c.lost)}|{len(c.tickets)}\n')
    r=R19(); c=Candidate()
    need(c.configure(SELECTED) == 'CONFIGURED','configure')
    put('selected_birth',r.birth(101),r,c)
    need(c.birth(101,1001,3001,9001,SELECTED)=='TRACK_SELECTED','selected birth')
    for i in range(1,1001):
        pid=2000+i
        old=r.birth(pid)
        modern=c.birth(pid,10000+i,10000+i,800000+i,SIBLING)
        need(modern == 'IGNORED_OUTSIDE_SCOPE','outside scope')
        put('unrelated_birth_'+str(i),old,r,c)
        put('unrelated_exit_'+str(i),r.death(pid),r,c)
        need(c.owner(101,1001,3001,9001)=='OK','unrelated churn independent')
    put('selected_r19_status',r.owner(101),r,c)
    need(r.lost,'r19 must be lost after global churn')
    need(len(c.live)==1 and not c.lost,'candidate remains scoped')
    old_ticket=c.issue(101,1001,3001,9001,77,FIVE)
    need(old_ticket is not None,'issue')
    put('issued_epoch_one',str(old_ticket),r,c)
    need(c.death(101,9001)=='RELEASE_REF_AFTER_RETIRE','release after exit')
    put('selected_exit','RELEASE_REF_AFTER_RETIRE',r,c)
    put('old_ticket_after_death',c.claim(old_ticket,101,1001,3001,9001,77,FIVE),r,c)
    need(c.birth(101,1002,3002,9002,SELECTED)=='TRACK_SELECTED','reuse pid new epoch')
    put('pid_reuse_new_epoch',c.owner(101,1002,3002,9002),r,c)
    put('stale_pid_epoch',c.owner(101,1001,3001,9001),r,c)
    fresh=c.issue(101,1002,3002,9002,77,FIVE)
    need(fresh is not None,'new issuance')
    put('reused_5tuple_fresh_ticket',c.claim(fresh,101,1002,3002,9002,77,FIVE),r,c)
    put('replay_ticket',c.claim(fresh,101,1002,3002,9002,77,FIVE),r,c)
    need(c.owner(101,1002,3002,9002)=='OK','new generation unpoisoned')
    late=Candidate()
    need(late.birth(201,2001,2002,2003,SELECTED)=='IGNORED_UNCONFIGURED','late blind')
    put('birth_before_configuration','IGNORED_UNCONFIGURED',r,late)
    need(late.configure(SELECTED)=='CONFIGURED','late config')
    put('late_configuration_no_backfill',late.owner(201,2001,2002,2003),r,late)
    need(late.issue(201,2001,2002,2003,99,FIVE) is None,'must not fabricate birth receipt')
    need(late.birth(202,2001,2002,2003,SELECTED)=='TRACK_SELECTED','new birth after config')
    put('post_config_new_birth',late.owner(202,2001,2002,2003),r,late)
    cap=Candidate()
    cap.configure(SELECTED)
    for i in range(1,5):
        put('selected_concurrent_'+str(i),cap.birth(i,i,i,100+i,SELECTED),r,cap)
    put('selected_fifth_rejected',cap.birth(5,5,5,105,SELECTED),r,cap)
    need(cap.death(1,101)=='RELEASE_REF_AFTER_RETIRE','cap release')
    put('selected_after_cap_release',cap.birth(5,5,5,105,SELECTED),r,cap)
    put('same_live_pid_conflict',cap.birth(5,99,99,999,SELECTED),r,cap)
    put('collision_must_block',cap.owner(5,5,5,105),r,cap)
    wrong=Candidate();wrong.configure(SELECTED);wrong.birth(777,2,3,444,SELECTED)
    put('mismatched_exit',wrong.death(777,999),r,wrong)
    put('mismatched_exit_latched',wrong.owner(777,2,3,444),r,wrong)
    require={'r19_lost':r.lost,'candidate_not_lost':not c.lost,'late_existing_denied':late.owner(201,2001,2002,2003)=='DENY_NO_KERNEL_BIRTH',
             'stale_claim_rejected':rows[2004].startswith('old_ticket_after_death|REJECT|')}
    need(all(require.values()),'campaign crucial assertions')
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--model-only',action='store_true');ap.add_argument('--source-root',type=Path,
        default=Path(__file__).resolve().parent.parent/'kernel-r19/kernel/src');args=ap.parse_args()
    if not args.model_only:source_gate(args.source_root)
    rows=campaign();print(json.dumps({'cases':len(rows),'sha256':hashlib.sha256(''.join(rows).encode()).hexdigest(),
      'source_pinned':not args.model_only,'native_rust_executed':False,'native_wfp_executed':False,'release_accepted':False},sort_keys=True))

if __name__=='__main__':main()
