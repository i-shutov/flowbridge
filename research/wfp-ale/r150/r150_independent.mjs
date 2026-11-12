// R150 independent pure Node state-transition oracle. No OS/network/drivers.
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const selected='opaque-appid:fully-qualified-selected';
const sibling='opaque-appid:same-basename-different-path';
const tuple='v4|tcp|192.0.2.10:3001|198.51.100.11:443';
const prior={all:new Set(),active:new Set(),lost:false};
function priorBorn(x){if(prior.lost)return 'DENY_LOST';if(prior.all.has(x)){prior.lost=true;return 'LATCH_REUSE';}if(prior.all.size===256){prior.lost=true;return 'LATCH_FULL';}prior.all.add(x);prior.active.add(x);return 'BORN'}
function priorDeath(x){prior.active.delete(x);return 'DIED'}
function priorLookup(x){return (!prior.lost&&prior.active.has(x))?'OK':'DENY'}
class Scoped {
 constructor(){this.selected=null;this.live=new Map();this.next=0;this.tokens=new Map();this.poisoned=false;this.limit=4}
 select(x){if(this.selected!==null||!x||this.poisoned){this.poisoned=true;return 'DENY_CONFIG'}this.selected=x;return 'CONFIGURED'}
 add(pid,epoch,key,ptr,img){if(this.poisoned)return 'DENY_LOST';if(this.selected===null)return 'IGNORED_UNCONFIGURED';
  if(img!==this.selected)return 'IGNORED_OUTSIDE_SCOPE';if(!pid||!epoch||!key||!ptr)return 'DENY_INVALID';
  if(this.live.has(pid)){this.poisoned=true;return 'LATCH_LIVE_COLLISION'}
  if(this.live.size>=this.limit)return 'DENY_SELECTED_CAP';
  this.live.set(pid,{epoch,key,ptr,version:++this.next});return 'TRACK_SELECTED'}
 remove(pid,ptr){if(this.poisoned)return 'DENY_LOST';const found=this.live.get(pid);
  if(!found)return 'IGNORED_EXIT';if(found.ptr!==ptr){this.poisoned=true;this.tokens.clear();return 'LATCH_EXIT_IDENTITY'}
  this.live.delete(pid);for(const [tid,t] of this.tokens){if(t.pid===pid)this.tokens.delete(tid)}return 'RELEASE_REF_AFTER_RETIRE'}
 check(pid,epoch,key,ptr){if(this.poisoned)return 'DENY_LOST';const x=this.live.get(pid);
  return (x&&x.epoch===epoch&&x.key===key&&x.ptr===ptr)?'OK':'DENY_NO_KERNEL_BIRTH'}
 create(pid,epoch,key,ptr,endpoint,five){if(this.check(pid,epoch,key,ptr)!=='OK')return null;
  const t=++this.next;this.tokens.set(t,{pid,epoch,key,ptr,version:this.live.get(pid).version,endpoint,five});return t}
 consume(tid,pid,epoch,key,ptr,endpoint,five){const prior=this.tokens.get(tid);this.tokens.delete(tid);
  if(this.poisoned||!prior)return 'REJECT';const live=this.live.get(pid);
  if(!live)return 'REJECT';
  const incoming={pid,epoch,key,ptr,version:live.version,endpoint,five};
  return Object.keys(prior).every(x=>prior[x]===incoming[x])?'MODEL_ROUTE':'REJECT'}
}
const records=[];
function log(label,result,model){records.push([label,result,prior.all.size,Number(prior.lost),model.live.size,Number(model.poisoned),model.tokens.size].join('|')+'\n')}
const scoped=new Scoped();assert.equal(scoped.select(selected),'CONFIGURED');
log('selected_birth',priorBorn(101),scoped);assert.equal(scoped.add(101,1001,3001,9001,selected),'TRACK_SELECTED');
for(let n=1;n<=1000;n++){
 const pid=2000+n;const first=priorBorn(pid),other=scoped.add(pid,10000+n,10000+n,800000+n,sibling);
 assert.equal(other,'IGNORED_OUTSIDE_SCOPE');log('unrelated_birth_'+n,first,scoped);
 log('unrelated_exit_'+n,priorDeath(pid),scoped);
 assert.equal(scoped.check(101,1001,3001,9001),'OK');
}
log('selected_r19_status',priorLookup(101),scoped);
assert.equal(prior.lost,true);assert.equal(scoped.live.size,1);
const old=scoped.create(101,1001,3001,9001,77,tuple);assert.notEqual(old,null);
log('issued_epoch_one',String(old),scoped);
assert.equal(scoped.remove(101,9001),'RELEASE_REF_AFTER_RETIRE');
log('selected_exit','RELEASE_REF_AFTER_RETIRE',scoped);
log('old_ticket_after_death',scoped.consume(old,101,1001,3001,9001,77,tuple),scoped);
assert.equal(scoped.add(101,1002,3002,9002,selected),'TRACK_SELECTED');
log('pid_reuse_new_epoch',scoped.check(101,1002,3002,9002),scoped);
log('stale_pid_epoch',scoped.check(101,1001,3001,9001),scoped);
const fresh=scoped.create(101,1002,3002,9002,77,tuple);assert.notEqual(fresh,null);
log('reused_5tuple_fresh_ticket',scoped.consume(fresh,101,1002,3002,9002,77,tuple),scoped);
log('replay_ticket',scoped.consume(fresh,101,1002,3002,9002,77,tuple),scoped);
assert.equal(scoped.check(101,1002,3002,9002),'OK');
const delayed=new Scoped();assert.equal(delayed.add(201,2001,2002,2003,selected),'IGNORED_UNCONFIGURED');
log('birth_before_configuration','IGNORED_UNCONFIGURED',delayed);
assert.equal(delayed.select(selected),'CONFIGURED');
log('late_configuration_no_backfill',delayed.check(201,2001,2002,2003),delayed);
assert.equal(delayed.create(201,2001,2002,2003,99,tuple),null);
assert.equal(delayed.add(202,2001,2002,2003,selected),'TRACK_SELECTED');
log('post_config_new_birth',delayed.check(202,2001,2002,2003),delayed);
const cap=new Scoped();cap.select(selected);
for(let n=1;n<=4;n++)log('selected_concurrent_'+n,cap.add(n,n,n,100+n,selected),cap);
log('selected_fifth_rejected',cap.add(5,5,5,105,selected),cap);
assert.equal(cap.remove(1,101),'RELEASE_REF_AFTER_RETIRE');
log('selected_after_cap_release',cap.add(5,5,5,105,selected),cap);
log('same_live_pid_conflict',cap.add(5,99,99,999,selected),cap);
log('collision_must_block',cap.check(5,5,5,105),cap);
const wrong=new Scoped();wrong.select(selected);wrong.add(777,2,3,444,selected);
log('mismatched_exit',wrong.remove(777,999),wrong);
log('mismatched_exit_latched',wrong.check(777,2,3,444),wrong);
assert.equal(delayed.check(201,2001,2002,2003),'DENY_NO_KERNEL_BIRTH');
assert.equal(scoped.poisoned,false);
assert.equal(records[2004].startsWith('old_ticket_after_death|REJECT|'),true);
console.log(JSON.stringify({cases:records.length,sha256:createHash('sha256').update(records.join('')).digest('hex'),source_pinned:false,native_rust_executed:false,native_wfp_executed:false,release_accepted:false}));
