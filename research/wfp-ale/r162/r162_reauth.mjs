// R162: independent JavaScript implementation of narrow AUTH_CONNECT contract.
// No Python imports and no Windows/WFP side effects.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
const priorTypes = ['PERMIT', 'CONTINUE', 'BLOCK'];
function answer(family, reauth, honoring, redirected, write, prior, match, attested, live) {
  if (![4, 6].includes(family)) throw new Error('family');
  if (!live) return 'NOT_INVOKED';
  if (!write) {
    if (prior === 'PERMIT') return 'BLOCK_VETO';
    return 'PRESERVE_' + prior;
  }
  if (reauth || honoring || !redirected || !match || attested) return 'BLOCK';
  return 'PERMIT_ONCE';
}
let cases = [];
for (const family of [4, 6])
for (const reauth of [false, true])
for (const honoring of [false, true])
for (const redirected of [false, true])
for (const write of [false, true])
for (const prior of priorTypes)
for (const matches of [false, true])
for (const attested of [false, true])
for (const filter_live of [false, true]) {
  cases.push({family, reauth, honoring, redirected, write, prior, matches,
    attested, filter_live,
    outcome: answer(family, reauth, honoring, redirected, write, prior,
      matches, attested, filter_live)});
}
const outcomes = Object.fromEntries([...new Set(cases.map(c=>c.outcome))].sort().map(k=>[k,cases.filter(c=>c.outcome===k).length]));
const expected = {schema:'FlowBridge-R162-reAuth-negative-v1',case_count:cases.length,outcomes,cases};
const path = new URL('./r162_reauth.py',import.meta.url).pathname;
const p = spawnSync('python3',['-B',path,'--json'],{encoding:'utf8',maxBuffer:1024*1024,env:{...process.env,PYTHONHASHSEED:'0'}});
if (p.status !== 0) throw new Error('python failed: '+p.stderr);
const received = JSON.parse(p.stdout.trim());
if (JSON.stringify(received.cases) !== JSON.stringify(expected.cases)) {
  // Python uses json.dumps(sort_keys=True), key order may differ. Check data, not source formatting.
  for (let i=0;i<cases.length;i++) {
    const a=cases[i],b=received.cases[i];
    for (const key of Object.keys(a)) if (a[key] !== b[key])
      throw new Error('oracle mismatch case=' + i + ' field=' + key + ': ' + a[key] + ' != ' + b[key]);
  }
}
if (received.case_count !== expected.case_count || JSON.stringify(received.outcomes)!==JSON.stringify(outcomes)) {
  throw new Error('aggregate mismatch');
}
const repr = JSON.stringify(outcomes);
console.log(JSON.stringify({ok:true,cases:cases.length,oracle_disagreements:0,outcomes,summary_sha256:createHash('sha256').update(repr).digest('hex')}));
