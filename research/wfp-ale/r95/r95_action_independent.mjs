// Separate Node oracle; exhaust 2^16 states for registration, four correct action
// types, four callout-key matches and four count/pointer checks. Shape held true.
import { createHash } from 'node:crypto';
const sha = createHash('sha256');
let original=0, repaired=0, falsePositive=0, rows=0;
for (let packed=0; packed<65536; packed++) {
  const reg=(packed>>>12)&15, type=(packed>>>8)&15;
  const key=(packed>>>4)&15, cond=packed&15;
  const baseline = reg===15 ? 1:0;
  const strict = ((reg & type & key & cond)===15) ? 1:0;
  const line=[reg,type,key,cond].map(x=>x.toString(16)).join(',')+','+baseline+','+strict+'\n';
  sha.update(line);
  original+=baseline;repaired+=strict;falsePositive+=baseline*(1-strict);rows++;
}
if (rows!==65536||original!==4096||repaired!==1||falsePositive!==4095) throw Error('bad matrix');
console.log('R95_MATRIX_SHA256',sha.digest('hex'),'ROWS',rows,'OLD',original,'NEW',repaired,'OLD_FALSE_POSITIVES',falsePositive);
