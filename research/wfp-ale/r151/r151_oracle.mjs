// Independent Node.js oracle; no imports from Python or WFP/Windows activity.
import {createHash} from 'node:crypto';
class Candidate {
 constructor(){this.live=new Map();this.tickets=new Map();this.seq=0;}
 birth(pid,epoch,key,ptr){this.live.set(pid,[epoch,key,ptr,++this.seq]);}
 death(pid,ptr){const o=this.live.get(pid);if(!o||o[2]!==ptr)throw Error('bad death');this.live.delete(pid);for(const [id,t] of this.tickets)if(t[0]===pid)this.tickets.delete(id);return 'RELEASE_REF_AFTER_RETIRE';}
 issue(pid,epoch,key,ptr,endpoint,five){const o=this.live.get(pid);if(!o||o[0]!==epoch||o[1]!==key||o[2]!==ptr)return null;const id=++this.seq;this.tickets.set(id,[pid,epoch,key,ptr,o[3],endpoint,five]);return id;}
 claim(id,pid,epoch,key,ptr,endpoint,five){const t=this.tickets.get(id);this.tickets.delete(id);const o=this.live.get(pid);return t&&o&&JSON.stringify(t)===JSON.stringify([pid,epoch,key,ptr,o[3],endpoint,five])?'MODEL_ROUTE':'REJECT';}
}
function check(ok){if(!ok)throw Error('ORACLE_INVARIANT_FAILED');}
const rows=[],ends=[0,1,7,77,4096,65535];
function fresh(pid=101,epoch=1001,key=3001,ptr=9001){const c=new Candidate();c.birth(pid,epoch,key,ptr);return c;}
for(const family of ['v4','v6']){
 for(const ep of ends)for(const swap of [0,1])for(const pid of [101,202]){
  const epoch=pid+100,key=pid+200,ptr=pid+300,c=fresh(pid,epoch,key,ptr);
  const five=`${family}|tcp|192.0.2.10:3001|198.51.100.11:443`,other=five+(swap?'|DIFFERENT_REMOTE':'');
  const a=c.issue(pid,epoch,key,ptr,ep,five),b=c.issue(pid,epoch,key,ptr,ep,other);
  const one=c.claim(a,pid,epoch,key,ptr,ep,five),two=c.claim(b,pid,epoch,key,ptr,ep,other),again=c.claim(a,pid,epoch,key,ptr,ep,five);
  check(a===2&&b===3&&one==='MODEL_ROUTE'&&two==='MODEL_ROUTE'&&again==='REJECT');
  rows.push(`alias|${family}|${ep}|${swap}|${pid}|${one}|${two}|${again}\n`);
 }
 {const c=fresh(),t=c.issue(101,1001,3001,9001,0,''),v=c.claim(t,101,1001,3001,9001,0,'');check(t===2&&v==='MODEL_ROUTE');rows.push(`zero|${family}|${v}\n`);}
 for(const ep of ends){
  const c=fresh(),a=c.issue(101,1001,3001,9001,ep,family);check(c.death(101,9001)==='RELEASE_REF_AFTER_RETIRE');
  const before=c.claim(a,101,1001,3001,9001,ep,family);c.birth(101,1002,3002,9002);
  const b=c.issue(101,1002,3002,9002,ep,family),after=c.claim(b,101,1002,3002,9002,ep,family);
  check(before==='REJECT'&&after==='MODEL_ROUTE');rows.push(`recycle|${family}|${ep}|${before}|${after}\n`);
 }
 {const c=fresh(),a=c.issue(101,1001,3001,9001,11,family),b=c.issue(101,1001,3001,9001,12,family);
  const one=c.claim(a,101,1001,3001,9001,11,family),two=c.claim(b,101,1001,3001,9001,12,family);
  check(one==='MODEL_ROUTE'&&two==='MODEL_ROUTE');rows.push(`control|${family}|${one}|${two}\n`);}
}
check(rows.length===64);
console.log(JSON.stringify({cases:64,alias_double_claim:48,zero_endpoint:2,recycle:12,controls:2,
 sha256:createHash('sha256').update(rows.join(''),'ascii').digest('hex'),native_wfp_executed:false,native_rust_executed:false,release_accepted:false}));
