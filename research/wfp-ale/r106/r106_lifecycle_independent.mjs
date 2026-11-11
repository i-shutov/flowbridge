// Independent explicit table oracle: NO WFP, sockets, process or network operations.
import {createHash} from 'node:crypto';
const phases=[['ARMED_BEFORE_POLICY','ABSENT'],['POLICY_LIVE','PRESENT'],
 ['SSH_LOSS_POLICY_LIVE','PRESENT'],['BROKER_EXIT','ABSENT'],
 ['GRACEFUL_POLICY_CLOSE','ABSENT'],['BFE_STATE_UNKNOWN','UNKNOWN']];
const rows=[];const counts={ABSENT:0,PRESENT:0,UNKNOWN:0,gap:0,candidate:0};
for(const [phase,coverage] of phases)
 for(let alive=0;alive<2;alive++)for(let attempt=0;attempt<2;attempt++)
 for(let guard=0;guard<2;guard++){
  const gap=(coverage==='ABSENT'&&alive===1&&attempt===1);
  const candidate=gap&&guard===0;
  counts[coverage]++;counts.gap+=Number(gap);counts.candidate+=Number(candidate);
  rows.push([phase,alive,attempt,guard,coverage,Number(gap),
   candidate?'CANDIDATE':'NOT_ESTABLISHED'].join('|'));
 }
if(rows.length!==48||counts.ABSENT!==24||counts.PRESENT!==16||
 counts.UNKNOWN!==8||counts.gap!==6||counts.candidate!==3)throw Error(JSON.stringify(counts));
if(rows.some(x=>x.includes('DIRECT_OBSERVED')))throw Error('runtime claim');
const digest=createHash('sha256').update(rows.join('\n')+'\n').digest('hex');
if(digest!=='5fef8e2d1307ca8d13ec949b4725e163fb0576ce074700b0f7382e78f48d3ef0')throw Error('matrix mismatch');
console.log('R106 NODE PASS 48 states, 6 owned-policy gap attempts, 3 candidates; sha256='+digest);
