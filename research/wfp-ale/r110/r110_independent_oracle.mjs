// Independent JS oracle: enumerate state vectors by integer index, not Python loops.
// No Windows API, network, driver, filtering action or side effects.
import { createHash } from 'node:crypto';
const oldChoices = [0,10,20,30];
const newChoices = [0,10,20,30];
const foreignChoices = [0,5,10,15,20,25,35];
const states = [];
const size = 4 * 4 * 4 * 7 * 2;
for (let n = 0; n < size; n++) {
  let x=n;
  const visible=x%2; x=Math.floor(x/2);
  const foreign=foreignChoices[x%7]; x=Math.floor(x/7);
  const now=newChoices[x%4]; x=Math.floor(x/4);
  const before=oldChoices[x%4]; x=Math.floor(x/4);
  const rule=x;
  const oldCandidate=before!==0 && visible!==0 && foreign>=before;
  let status='UNKNOWN';
  if (now>0) status=(visible!==0 && foreign>=now)?'VISIBLE_ARBITRATION_CANDIDATE':'UNKNOWN_NO_VISIBLE_CANDIDATE';
  states.push([rule,before,now,foreign,visible,Number(oldCandidate),status]);
}
const digest=createHash('sha256').update(states.map(s=>s.join('|')).join('\n')+'\n').digest('hex');
const result={
  cases:states.length,
  missing_baseline_unknown:states.filter(x=>x[6]==='UNKNOWN').length,
  old_mixed_snapshot_overreports:states.filter(x=>x[5]===1 && x[6]!=='VISIBLE_ARBITRATION_CANDIDATE').length,
  old_mixed_snapshot_underreports:states.filter(x=>x[5]===0 && x[6]==='VISIBLE_ARBITRATION_CANDIDATE').length,
  decision_sha256:digest,
  native_windows_executed:false,kernel_proof:false
};
if(result.cases!==896||result.old_mixed_snapshot_overreports===0||result.old_mixed_snapshot_underreports===0) throw Error('negative counterexamples absent');
console.log(JSON.stringify(result,null,2));
