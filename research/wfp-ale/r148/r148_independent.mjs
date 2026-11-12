// R148: independent JavaScript oracle of R19 lab Book limits. No OS or WFP calls.
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
const maxLive = 32, maxTombs = 4096, ttl = 100_000_000;
class Ledger {
  constructor() { this.live = new Map(); this.used = new Set(); this.dead = false; }
  begin(id, now) {
    if (this.dead || id <= 0 || now <= 0) return 'DENY';
    for (const [key,time] of this.live) if(now - time > ttl) this.live.delete(key);
    if (this.used.has(id)) { this.dead=true; return 'LATCH_REUSED_ENDPOINT'; }
    if (this.used.size === maxTombs) { this.dead=true; return 'LATCH_TOMBSTONE_EXHAUSTED'; }
    if (this.live.size === maxLive) return 'BLOCK_LIVE_CAP';
    this.used.add(id);this.live.set(id,now);return 'ISSUED';
  }
  retire(id) { this.live.delete(id); }
  stop() { this.dead=true; this.live.clear(); }
}
const hash=createHash('sha256');let cases=0;
const counts=Object.fromEntries(['ISSUED','BLOCK_LIVE_CAP','LATCH_REUSED_ENDPOINT','LATCH_TOMBSTONE_EXHAUSTED','DENY'].map(k=>[k,0]));
function add(label, result, book) {
 hash.update(`${label}|${result}|${book.live.size}|${book.used.size}|${Number(book.dead)}\n`,'ascii');
 counts[result]++;cases++;
}
let b=new Ledger();
for(let id=1;id<=maxLive+1;id++) add('burst_'+id,b.begin(id,1),b);
assert.equal(b.used.size,maxLive);assert.equal(b.dead,false);
b.retire(1);add('reclaim_slot',b.begin(maxLive+2,2),b);
assert.equal(b.used.size,maxLive+1);
b=new Ledger();
for(let id=1;id<=maxTombs+1;id++){
 const result=b.begin(id,id);add('sequential_'+id,result,b);
 if(result==='ISSUED')b.retire(id);
}
assert.equal(b.used.size,maxTombs);assert.equal(b.dead,true);
add('after_budget_loss',b.begin(maxTombs+2,maxTombs+2),b);
b=new Ledger();add('original',b.begin(17,1),b);b.retire(17);
add('reuse_same_endpoint',b.begin(17,2),b);
add('fresh_after_reuse',b.begin(18,3),b);assert(b.dead);
b=new Ledger();for(let id=1;id<=maxLive;id++)b.begin(id,1);
add('ttl_reclaim',b.begin(maxLive+1,ttl+2),b);
assert.equal(b.live.size,1);assert.equal(b.used.size,maxLive+1);
b=new Ledger();b.begin(1,1);b.stop();add('killed',b.begin(2,3),b);assert(b.dead);
console.log(JSON.stringify({model_cases:cases,counts,
 matrix_sha256:hash.digest('hex'),source_pinned:false,native_windows_executed:false,
 release_accepted:false,no_direct_proved:false}));
