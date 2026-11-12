// R149 independent deterministic ledger churn oracle, no OS/kernel/network.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
class Ledger {
  constructor(){this.records=[];this.poisoned=false;}
  birth(pid,valid=true){
    if(!valid)return 'SKIPPED_INELIGIBLE';
    if(this.poisoned)return 'DENIED_LOST';
    const existing=this.records.find(x=>x.pid===pid);
    if(existing){existing.live=false;this.poisoned=true;return 'LATCH_PID_REUSE';}
    if(this.records.length===256){this.poisoned=true;return 'LATCH_OWNER_LIMIT';}
    this.records.push({pid,live:true});return 'BORN';
  }
  exit(pid){const p=this.records.find(x=>x.pid===pid);if(p)p.live=false;return 'DIED';}
  look(pid){return !this.poisoned && this.records.some(x=>x.pid===pid && x.live)?'LOOKUP_OK':'LOOKUP_DENIED';}
}
const rows=[];
const add=(label,event,m)=>rows.push(`${label}|${event}|${m.records.length}|${Number(m.poisoned)}\n`);
const a=new Ledger();add('selected_alive',a.birth(101),a);
for(let i=1;i<256;i++){
 const pid=1000+i;
 add(`unrelated_birth_${i}`,a.birth(pid),a);
 add(`unrelated_exit_${i}`,a.exit(pid),a);
}
add('selected_before_257',a.look(101),a);
add('unrelated_257',a.birth(1256),a);
add('selected_after_257',a.look(101),a);
add('even_new_selected_denied',a.birth(102),a);
assert.equal(a.records.length,256);assert.equal(a.poisoned,true);
const b=new Ledger();add('reuse_selected',b.birth(201),b);
add('reuse_unrelated_first',b.birth(222),b);
add('reuse_unrelated_exit',b.exit(222),b);
add('reuse_unrelated_second',b.birth(222),b);
add('selected_after_unrelated_reuse',b.look(201),b);
assert.equal(b.records.length,2);assert.equal(b.poisoned,true);
const c=new Ledger();for(let i=1;i<260;i++)add(`ineligible_${i}`,c.birth(i,false),c);
add('first_eligible_after_skips',c.birth(401),c);
assert.equal(c.records.length,1);assert.equal(c.poisoned,false);
const d=new Ledger();add('owner_before_early_reuse',d.birth(777),d);
add('live_pid_collision',d.birth(777),d);
add('cannot_lookup_collided',d.look(777),d);
assert.equal(d.poisoned,true);
console.log(JSON.stringify({cases:rows.length,sha256:createHash('sha256').update(rows.join('')).digest('hex'),source_pinned:false,native_wfp_executed:false,release_accepted:false,no_direct_proved:false}));
