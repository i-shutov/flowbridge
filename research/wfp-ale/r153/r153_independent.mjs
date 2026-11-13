// Independently enumerated partial-order closure vs AUTH interleavings.
// No WFP, no network, no Python imports. No Windows scheduling claim.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const names = ['ISSUE_OLD', 'AUTH_OLD_ENTER', 'CLOSE_ENTER', 'CLOSE_PEND',
               'CLOSE_OWN_WORK_DONE', 'CLOSE_COMPLETE', 'ISSUE_NEW',
               'AUTH_OLD_RESUME', 'AUTH_NEW'];
const prerequisites = new Map([
 ['ISSUE_OLD', []], ['AUTH_OLD_ENTER', ['ISSUE_OLD']],
 ['CLOSE_ENTER', ['ISSUE_OLD']], ['CLOSE_PEND', ['CLOSE_ENTER']],
 ['CLOSE_OWN_WORK_DONE', ['CLOSE_PEND']], ['CLOSE_COMPLETE', ['CLOSE_OWN_WORK_DONE']],
 ['ISSUE_NEW', ['CLOSE_COMPLETE']], ['AUTH_OLD_RESUME', ['AUTH_OLD_ENTER']],
 ['AUTH_NEW', ['ISSUE_NEW']]
]);
const permutations = [];
function enumerate(done, chosen) {
 if (chosen.length === names.length) { permutations.push([...chosen]); return; }
 for (const next of names) {
   if(done.has(next) || !prerequisites.get(next).every(x => done.has(x))) continue;
   done.add(next); chosen.push(next);
   enumerate(done,chosen);
   chosen.pop();done.delete(next);
 }
}
enumerate(new Set(),[]);
assert(permutations.length > 0);
const hash = createHash('sha256');
const tally = Object.create(null);
for (const family of [4,6]) {
 for (const same of [0,1]) {
  for (const reuse of [0,1]) {
   for (const s of permutations) {
     const oldLate = s.indexOf('AUTH_OLD_RESUME') > s.indexOf('ISSUE_NEW');
     let label;
     if (!reuse) label = 'REUSE_QUARANTINED';
     else if (!oldLate) label = 'OLD_AUTH_BEFORE_NEW_ISSUANCE';
     else label = same ? 'STALE_AUTH_ALIAS' : 'OBSERVABLE_DIFFERENCE';
     hash.update(`${family}|${same}|${reuse}|${s.join(',')}|${label}\n`, 'ascii');
     tally[label] = (tally[label] || 0) + 1;
   }
  }
 }
}
assert(tally.STALE_AUTH_ALIAS > 0 && tally.REUSE_QUARANTINED === permutations.length*4);
assert.equal(tally.STALE_AUTH_ALIAS,tally.OBSERVABLE_DIFFERENCE);
const categories = Object.fromEntries(Object.entries(tally).sort((a,b)=>a[0].localeCompare(b[0],'en')));
const result = {schedules:permutations.length,cases:permutations.length*8,sha256:hash.digest('hex'),
 categories,native_wfp_executed:false,actual_reuse_observed:false,
 cross_layer_barrier_proved:false,release_accepted:false};
console.log(JSON.stringify(result));
