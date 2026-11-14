// Independent, pure Node.js source-guard oracle. Not a WFP classifier, not a proof of packets.
const fam=[4,6], stages=['policy_honor_original','redirected_loopback','record_tagged_ssh','sibling_direct'];
const names=['selected','broker'];
let total=0, pre=0, phys=0, sibling=0, positiveProxy=0;
for (const family of fam) {
 for (const stage of stages) {
  for (let flagged=0;flagged<8;flagged++) {
   const flags=((flagged&1)?1048576:0)+((flagged&2)?2097152:0)+((flagged&4)?33554432:0);
   for (const original of names) for (const owner of names)
    for (const metadata of [false,true]) for (const ticket of [false,true])
     for (const correct_port of [false,true]) {
      const selected=original==='selected';
      const authFlag=(flags&1048576)!==0 && (flags&33554432)===0;
      const localTarget=(stage==='redirected_loopback') && correct_port;
      const originLive=owner==='selected';
      const accepted=selected && metadata && authFlag && localTarget && originLive && ticket;
      const result=!selected?'OUTSIDE_FILTER':accepted?'ATTEST_CANDIDATE_ONLY':'SOURCE_BLOCK_REQUEST';
      const row={family,stage,flags,original,owner,metadata,ticket,correct_port,result};
      const ordered={};Object.keys(row).sort().forEach(k=>ordered[k]=row[k]);
      console.log(JSON.stringify(ordered));total++;
      if(stage==='policy_honor_original' && (flags&33554432)!==0 && selected && result==='SOURCE_BLOCK_REQUEST')pre++;
      if(stage==='record_tagged_ssh' && (flags&2097152)!==0 && selected && result==='SOURCE_BLOCK_REQUEST')phys++;
      if(stage==='sibling_direct' && selected && result==='SOURCE_BLOCK_REQUEST')sibling++;
      if(accepted && (flags&2097152)!==0)positiveProxy++;
     }
  }
 }
}
if(total!==2048||pre!==128||phys!==128||sibling!==256||positiveProxy===0)throw Error(`oracle assertion ${total} ${pre} ${phys} ${sibling} ${positiveProxy}`);
