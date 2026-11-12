// R147 independent Node.js oracle; no Windows, sockets, installed filters.
import { createHash } from 'node:crypto';
const counts = new Map();
let rows = '', emptyCases = 0, n = 0;
for (const family of ['v4','v6']) {
  for (const app of ['selected','empty','foreign','absent']) {
    for (const tcp of [0,1]) for(const phase of ['initial','reauth']) {
      for (const active of [0,1]) for (const alive of [0,1]) for (const earlier of [0,1]) {
        let outcome;
        if (active === 0) outcome = 'FILTER_ABSENT_NO_CLAIM';
        else if (app !== 'selected' || tcp === 0) outcome = 'FILTER_NONMATCH_NO_CALLBACK';
        else if (earlier === 1) outcome = 'FILTER_MATCH_MAY_BE_SKIPPED';
        else outcome = 'FILTER_ELIGIBLE_NOT_KERNEL_PROOF';
        if (app === 'empty' && phase === 'reauth' && active && alive && tcp) {
          if (outcome !== 'FILTER_NONMATCH_NO_CALLBACK') throw new Error('EMPTY_REAUTH');
          emptyCases++;
        }
        if (app === 'selected' && tcp && active && !earlier && outcome !== 'FILTER_ELIGIBLE_NOT_KERNEL_PROOF') {
          throw new Error('MISSED_FILTER_CANDIDATE');
        }
        counts.set(outcome,(counts.get(outcome)||0)+1);
        rows += [family,app,tcp,phase,active,alive,earlier,outcome].join('|')+'\n'; n++;
      }
    }
  }
}
if (n !== 256 || emptyCases !== 4) throw new Error('SHAPE');
const result = {rows:n,empty_reauth_live_hypothetical:emptyCases,
 counts:Object.fromEntries([...counts].sort(([a],[b])=>a.localeCompare(b))),
 matrix_sha256:createHash('sha256').update(rows).digest('hex'),
 appid_empty_at_reauth_observed:false,callback_invocation_observed:false,
 direct_egress_observed:false,native_filter_execution:false,
 packetbound_g2_pass:false,release_go:false};
process.stdout.write(JSON.stringify(result)+'\n');
