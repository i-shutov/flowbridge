// R64 independent Node negative oracle; no networking, WFP or Git operations.
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const IOC_VENDOR = 0x18000000, IOC_OUT = 0x40000000;
const correct = (IOC_VENDOR | IOC_OUT | 205) >>> 0;
const wrong = (0x08000000 | IOC_OUT | 3) >>> 0;
assert.equal(correct, 1476395213);
assert.notEqual(correct, wrong);
let stream = '';
let stats = {states:0,unobserved:0,invalid:0,endpoint_only:0,hypothetical_strong:0};
for(let n=0;n<4096;n++){
  const has = bit=>Boolean(n & (1<<bit));
  let outcome='';let hypothetical=false;
  if(!has(0)) {outcome='UNOBSERVED';stats.unobserved++;}
  else {
    let good = true;
    for(const i of [1,2,3,4,5,6,7,8,11]) good &&= has(i);
    if(!good) {outcome='INVALID_DIAGNOSTIC';stats.invalid++;}
    else {outcome='ENDPOINT_ONLY_NOT_OWNER';stats.endpoint_only++;
      hypothetical=has(9) && has(10);
      if(hypothetical) stats.hypothetical_strong++;
    }
  }
  stats.states++;
  stream += outcome+'|'+(hypothetical?1:0)+'\n';
}
stats.correct_ioctl=correct;
stats.old_wrong_ioctl=wrong;
stats.decision_sha256=createHash('sha256').update(stream).digest('hex');
assert.equal(stats.unobserved,2048);
assert(stats.endpoint_only>stats.hypothetical_strong);
console.log(JSON.stringify(stats));
