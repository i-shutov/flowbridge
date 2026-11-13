#!/usr/bin/env node
// Independently constructed event-alphabet finite-state oracle, no kernel I/O.
import {createHash} from 'node:crypto';
const alphabet=['birth','exit','reuse','redirect4','redirect6','auth4','auth6','pop'];
function test(seq){
  let count=0,failed=false;const replies=[];
  for(const event of seq){
    if(event==='birth'&&!failed){if(count<256)count++;else failed=true;}
    else if(event==='reuse'&&count)failed=true;
    else if(event==='pop')replies.push(failed?'NOT_READY':'EMPTY');
    else if(!alphabet.includes(event))throw Error('invalid event');
  }
  return replies.join(',')+'|'+count+'|'+Number(failed)+'|0';
}
let total=0,reads=0;const sha=createHash('sha256');
for(let len=0;len<=5;len++)for(let i=0;i<8**len;i++){
  const seq=new Array(len);let x=i;
  for(let n=len-1;n>=0;n--){seq[n]=alphabet[x%8];x=Math.floor(x/8);}
  const result=test(seq);
  if(result.includes('SUCCESS'))throw Error('witness unexpectedly generated');
  sha.update(seq.join(',')+'|'+result+'\n');
  total++;reads+=seq.filter(x=>x==='pop').length;
}
const cap=test([...Array(257).fill('birth'),'pop']);
if(cap!=='NOT_READY|256|1|0')throw Error('cap contract wrong');
console.log(JSON.stringify({traces:total,pop_events:reads,witness_success:0,
 sha256:sha.digest('hex'),capacity_trace:cap}));
