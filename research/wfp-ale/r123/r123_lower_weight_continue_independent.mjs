// R123 independently implemented Node oracle: read-only, no WFP, no network.
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
// The four R19 rules are indexed AUTH4,AUTH6,REDIRECT4,REDIRECT6.
const rules=['terminating','terminating','unknown','unknown'];
let lines=[];let repaired=0;let visible=0;
for(let k=0;k<rules.length;k++){
  for(let a=0;a<4;a++)for(let b=0;b<4;b++)for(let c=0;c<4;c++){
    const was=(a+b)>0;
    const now=was||(rules[k]==='unknown'&&c!==0);
    if(now)visible++;
    if(now&&!was)repaired++;
    lines.push(`${k},${a},${b},${c},${Number(was)},${Number(now)}`);
  }
}
assert.equal(lines.length,256);
assert.equal(repaired,6);
assert.equal(visible,246);
const sha=createHash('sha256').update(lines.join('\n')+'\n','ascii').digest('hex');
console.log('R123_MATRIX '+JSON.stringify({cases:lines.length, corrected_lower_only:repaired,
  new_candidates:visible, matrix_sha256:sha, native_wfp_observed:false,
  no_direct_proven:false, kernel_origin_proven:false}));
