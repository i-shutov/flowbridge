// R66 independent offline negative oracle. No OS/WFP calls.
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
const observedBits=11, hiddenBits=5, allVisible=(1<<observedBits)-1, allHidden=(1<<hiddenBits)-1;
const counts={U:0,I:0,D:0,V:0,weak_numeric_permits:0};
const hash=createHash('sha256');
function decide(v,h) {if(!(v&1)) return 'U'; if(v!==allVisible) return 'I'; return h===allHidden?'V':'D';}
for(const family of [4,6]) for(let v=0;v<(1<<observedBits);v++) for(let h=0;h<(1<<hiddenBits);h++) {
 const state=decide(v,h),weak=v===allVisible?1:0;
 counts[state]++;counts.weak_numeric_permits+=weak;hash.update(`${family}${state}${weak}\n`);
}
counts.weak_excess_against_hypothetical=counts.weak_numeric_permits-counts.V;
counts.total=counts.U+counts.I+counts.D+counts.V;
assert.equal(counts.total,131072);assert.equal(counts.V,2);
assert.equal(counts.weak_numeric_permits,64);assert.equal(counts.weak_excess_against_hypothetical,62);
assert.equal(decide(allVisible,allHidden^1),'D');assert.equal(decide(allVisible^1,allHidden),'U');
console.log(JSON.stringify({counts,stream_sha256:hash.digest('hex'),scope:'purely synthetic; V is not Windows proof'}));
