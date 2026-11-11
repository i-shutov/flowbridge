// R100 independent boolean decision-table oracle. No WFP, network or driver.
import {createHash} from 'node:crypto';
function verdict(bits) {
  const [S,I,W,E,A,P,R]=bits.map(Boolean);
  let red='OUT_OF_SCOPE';
  if(S){red=!I?'NO_REDIRECT_CALLOUT':!W?'UNDETERMINED_NO_WRITE_RIGHT':
    !E?'CONTINUE':!R?'DRIVER_BLOCK':'REDIRECT_CANDIDATE';}
  const auth=red==='CONTINUE'?(A?'AUTH_DRIVER_BLOCK':'AUTH_NOT_INVOKED'):
    (S?'NOT_EVALUATED':'NA');
  return bits.join('')+','+red+','+auth+','+Number(red==='CONTINUE'&&!A&&P);
}
const rows=Array.from({length:128},(_,n)=>
  verdict(Array.from({length:7},(_,i)=>(n>>(6-i))&1)));
if(rows.length!==128)throw Error('rows');
if(verdict([1,1,1,0,0,1,1]).split(',').slice(1).join(',')!=='CONTINUE,AUTH_NOT_INVOKED,1')throw Error('witness');
if(verdict([1,1,1,0,1,1,1]).split(',').slice(1).join(',')!=='CONTINUE,AUTH_DRIVER_BLOCK,0')throw Error('AUTH');
const data=rows.join('\n')+'\n';
console.log('rows=128 continue='+rows.filter(x=>x.includes(',CONTINUE,')).length+
' conditional_potential_direct='+rows.filter(x=>x.endsWith(',1')).length);
console.log('sha256='+createHash('sha256').update(data).digest('hex'));
