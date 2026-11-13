// Independent JS state transformer for R19's outer callback + inner early return.
// No network/socket/driver/WFP API; outcomes are CALLBACK OUTPUT, not traffic.
import {createHash} from 'node:crypto';
const phases=['SELF_RETURN','APPID_MISMATCH','NOT_CONFIGURED','RUNDOWN_DENIED','STOPPED','BAD_METADATA','OTHER_INSPECTOR'];
const states=['SELF','PREVIOUS_SELF'];
const actions=['PERMIT','BLOCK','CONTINUE','NONE'];
const totals={};
let differing=0, n=0;
const digest=createHash('sha256');
for (const ipVersion of [4,6]) for(const state of states) for(const previous of actions)
  for (const hasWriteRight of [0,1]) for(const phase of phases) {
    let output=previous, right=hasWriteRight;
    // lib.rs writes CONTINUE, before rundown and before redirect::classify.
    if (right) output='CONTINUE';
    // For early return, the inner callback never writes an action.
    const returnsEarly=(phase==='SELF_RETURN'||phase==='APPID_MISMATCH');
    let why;
    if (returnsEarly) why=right?'OUTER_CONTINUE':'PRESERVED_NO_WRITE';
    else if (right) {output='BLOCK';right=0;why='BLOCK_WITH_WRITE';}
    else if (output==='PERMIT') {output='BLOCK';why='VETO_PERMIT_NO_WRITE';}
    else why='PRESERVED_NO_WRITE';
    totals[why]=(totals[why]||0)+1;
    if(phase==='SELF_RETURN' && output!==previous) differing++;
    digest.update(`${ipVersion}|${state}|${previous}|${hasWriteRight}|${phase}|${output}|${right}|${why}\n`,'ascii');
    n++;
}
const expected={OUTER_CONTINUE:32, PRESERVED_NO_WRITE:92, BLOCK_WITH_WRITE:80, VETO_PERMIT_NO_WRITE:20};
if(n!==224||differing!==12||Object.keys(expected).some(k=>expected[k]!==totals[k])) throw Error('matrix drift');
console.log(JSON.stringify({cases:n,changed_r155_action_rows:differing,counts:totals,
  sha256:digest.digest('hex'),model_only:true,kernel_executed:false,release_accepted:false,no_direct_proved:false}));
