// R63 separate JavaScript state enumerator. Does not import or call Python/Rust.
import { createHash } from 'node:crypto';
const observableCount = 12;
const count = 2 ** 16;
const seen = (2 ** observableCount) - 1;
const hidden = 15 * (2 ** observableCount);
const result = {
  states: 0, unobserved: 0, invalid: 0, diagnostic_only: 0,
  hypothetical_strict: 0, weak_without_original: 0,
  weak_after_physical_death: 0, weak_without_record_join: 0,
};
const sha = createHash('sha256');
function evaluate(s) {
  if (s % 2 === 0) return 'U';
  if ((s & seen) !== seen) return 'R';
  return 'D';
}
for (let n=0;n<count;n++) {
  const d=evaluate(n);
  sha.update(d,'ascii');
  result.states++;
  if (d === 'U') result.unobserved++;
  else if(d === 'R') result.invalid++;
  else {
    result.diagnostic_only++;
    if((n & hidden) === hidden) result.hypothetical_strict++;
    if((n & (1<<12)) === 0) result.weak_without_original++;
    if((n & (1<<15)) === 0) result.weak_after_physical_death++;
    if((n & (1<<14)) === 0) result.weak_without_record_join++;
  }
}
result.ordered_decision_sha256=sha.digest('hex');
result.indistinguishable_witnesses=[seen,seen|hidden];
if (evaluate(seen) !== evaluate(seen|hidden) || result.hypothetical_strict !== 1)
  throw Error('Oracle invariant violated');
console.log(JSON.stringify(result));
