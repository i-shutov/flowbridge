// Independent, dependency-free oracle for explicit WFP action provenance.
// Finite logic only, not live callbacks, source compilation, or packet proof.
import { createHash } from 'node:crypto';
const paths = ['redirect_no_right', 'auth_no_right', 'kernel_rundown', 'kernel_stop'];
const actions = ['PERMIT', 'BLOCK', 'CONTINUE', 'NONE'];
const origins = ['HIGHER_WEIGHT_PERMIT', 'OTHER_OR_ABSENT', 'UNKNOWN'];
const count = {DOCUMENTED: 0, CONTRACT_GAP: 0, UNPROVEN: 0};
const hash = createHash('sha256');
let n = 0;
for (const path of paths) {
  for (const ip of [4, 6]) {
    for (const right of [0, 1]) {
      for (const action of actions) {
        for (const origin of origins) {
          let status;
          if (right === 1 || (action === 'PERMIT' && origin === 'HIGHER_WEIGHT_PERMIT')) {
            status = 'DOCUMENTED';
          } else if (right === 0 && action === 'PERMIT' && origin === 'UNKNOWN') {
            status = 'UNPROVEN';
          } else {
            status = 'CONTRACT_GAP';
          }
          hash.update([path, ip, right, action, origin, status].join('|') + '\n');
          count[status]++;
          n++;
        }
      }
    }
  }
}
const result = {total: n, counts: Object.fromEntries(Object.entries(count).sort()), sha256: hash.digest('hex')};
if (n !== 192 || result.counts.DOCUMENTED !== 104 || result.counts.CONTRACT_GAP !== 80 || result.counts.UNPROVEN !== 8) throw Error('model regression');
console.log(JSON.stringify(result));
