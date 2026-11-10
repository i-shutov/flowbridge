/* Independent R91 model; no OS, network or Rust code imported. */
import {createHash} from 'node:crypto';
const CAP=256;
function create(){return {slots:new Map(),fail:false}}
function insert(s,p){
  if(s.fail)return 'Lost';
  if(s.slots.has(p)){s.slots.set(p,false);s.fail=true;return 'ReusedPid';}
  if(s.slots.size>=CAP){s.fail=true;return 'Full';}
  s.slots.set(p,true);return 'OK';
}
function exit(s,p){if(s.slots.has(p))s.slots.set(p,false)}
function snapshot(name,step,code,s,sel){
  let living=0;for(const v of s.slots.values())if(v)living++;
  const canSee=!s.fail&&s.slots.get(sel)===true;
  return [name,step,code,s.slots.size,living,Number(s.fail),Number(canSee)];
}
const results=[];
let s=create(),n='selected-survives-churn',selected=1;
results.push(snapshot(n,'selected-birth',insert(s,1),s,selected));
for(let pid=2;pid<=256;pid++)insert(s,pid);
results.push(snapshot(n,'255-unrelated-born','OK',s,selected));
for(let pid=2;pid<=256;pid++)exit(s,pid);
results.push(snapshot(n,'255-unrelated-exited','OK',s,selected));
results.push(snapshot(n,'257th-unique-birth',insert(s,257),s,selected));
results.push(snapshot(n,'selected-lookup-after-cap','lookup',s,selected));
s=create();n='unrelated-pid-reuse';insert(s,1);insert(s,2);exit(s,2);
results.push(snapshot(n,'two-born-one-dead','OK',s,1));
results.push(snapshot(n,'unrelated-pid-2-reborn',insert(s,2),s,1));
results.push(snapshot(n,'selected-lookup-after-reuse','lookup',s,1));
s=create();n='unrelated-preemption';for(let pid=1;pid<=256;pid++)insert(s,pid);
results.push(snapshot(n,'256-unrelated-born','OK',s,999));
results.push(snapshot(n,'selected-257th-birth',insert(s,999),s,999));
s=create();n='all-exited-still-full';for(let pid=1;pid<=256;pid++)insert(s,pid);
for(let pid=1;pid<=256;pid++)exit(s,pid);
results.push(snapshot(n,'all-256-exited','OK',s,999));
results.push(snapshot(n,'new-selected-birth',insert(s,999),s,999));
if(results.length!==12||results[3][2]!=='Full'||results[6][2]!=='ReusedPid'||
   results[9][2]!=='Full'||results[11][2]!=='Full'||results[2][4]!==1)throw Error('R91 independent control failed');
const data=results.map(r=>r.join('|')+'\n').join('');
console.log('R91_NODE_RECORDS='+results.length);
console.log('R91_SHA256='+createHash('sha256').update(data).digest('hex'));
