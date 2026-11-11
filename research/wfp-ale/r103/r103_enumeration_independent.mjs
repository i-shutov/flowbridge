// Independent enumeration safety oracle; no OS/network/Windows operations.
import {createHash} from 'node:crypto';
const weightNames=['LOW','TIE','HIGH','NONE'];
const lines=[];
const totals={UNKNOWN_ERROR:0,VISIBLE_CANDIDATE:0,UNKNOWN_NO_VISIBLE:0};
for(let f=0;f<2;f++)for(let s=0;s<2;s++)for(let w=0;w<4;w++)
 for(let seen=0;seen<2;seen++)for(let paged=0;paged<2;paged++)
 for(let baseline=0;baseline<2;baseline++)for(let hidden=0;hidden<2;hidden++){
  // Independently calculate a conservative candidate using logical truth table.
  const candidate=(w===1||w===2)&&seen===1;
  const valid=Boolean(paged&&baseline);
  const result=!valid?'UNKNOWN_ERROR':candidate?'VISIBLE_CANDIDATE':'UNKNOWN_NO_VISIBLE';
  if(hidden===1&&seen===0&&valid&&result!=='UNKNOWN_NO_VISIBLE')throw Error('ACL false negative');
  if(result==='POLICY_SAFE')throw Error('unsafe affirmative');
  totals[result]++;
  lines.push([f,s,weightNames[w],seen,paged,baseline,hidden,result].join('|'));
 }
if(lines.length!==256||totals.UNKNOWN_ERROR!==192||totals.VISIBLE_CANDIDATE!==16||totals.UNKNOWN_NO_VISIBLE!==48)
 throw Error('counts mismatch: '+JSON.stringify(totals));
const hash=createHash('sha256').update(lines.join('\n')+'\n').digest('hex');
console.log('R103 NODE PASS: '+lines.length+' states; counts='+JSON.stringify(totals)+'; digest='+hash);
console.log(lines.find(x=>x.includes('|HIGH|1|1|1|0|VISIBLE_CANDIDATE')));
console.log(lines.find(x=>x.includes('|NONE|0|1|1|1|UNKNOWN_NO_VISIBLE')));
