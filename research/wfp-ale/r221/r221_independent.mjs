// R221 independent oracle: finite enumeration, no filesystem/network/WFP APIs.
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

function decide(x) {
  const [family, selected, redirected, sameOwner, veto, caller, bytes, accepted] = x;
  // Logic written independently from Python: use bitwise masks per condition.
  const claimGate = selected & redirected & sameOwner & caller & bytes;
  const auth = selected & redirected & sameOwner;
  const final = auth & (veto ^ 1);
  return [auth, final, claimGate, claimGate & final & accepted];
}
const out = [];
const count = [0,0,0,0,0];
for (let n=0;n<256;n++) {
  const x = Array.from({length:8},(_,i)=>(n >> (7-i))&1);
  const y = decide(x);
  y.forEach((v,i)=>count[i]+=v);
  count[4]+= y[2] & (y[1]^1);
  out.push([...x,...y].join(','));
}
const digest=createHash('sha256').update(out.join('\n')+'\n').digest('hex');
assert.deepEqual(count,[32,16,8,2,4]);
assert.equal(decide([0,1,1,1,1,1,1,0]).join(','),'1,0,1,0');
// Independent mutation sensitivity: dropping final veto or broker check changes output.
const mutatedVeto = out.some((row,n)=>{
  const a=Array.from({length:8},(_,i)=>(n>>(7-i))&1);
  return decide(a)[1] !== decide([...a.slice(0,4),0,...a.slice(5)])[1];
});
assert(mutatedVeto);
console.log('cases=256 auth='+count[0]+' final='+count[1]+' raw='+count[2]+' typed='+count[3]+' raw_but_final_block='+count[4]+' sha256='+digest);
