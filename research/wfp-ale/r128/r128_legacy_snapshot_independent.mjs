import {createHash} from 'node:crypto';
// Independent offline model. No native BFE or WFP calls.
function verdict(rule,buckets,visible,hardened) {
  if(hardened) {
    if(buckets.some(v=>typeof v!=='number'||!Number.isInteger(v)||v<0||v>131072))return 2;
    if(!Number.isInteger(visible)||visible<4||visible>131072||buckets.reduce((a,b)=>a+b,0)>visible-4)return 2;
  } else {
    if(buckets.some(v=> !(typeof v==='number'||typeof v==='boolean')||Number(v)<0))return 2;
  }
  const positive=v=>Number(v)>0;
  return positive(buckets[0])||positive(buckets[1])||(hardened&&rule>=2&&positive(buckets[2]))?3:4;
}
const rows=[],counts={};let idx=0;
for(let rule=0;rule<4;rule++)for(let field=0;field<4;field++)
for(const value of [0,1,0.5,-1,true])for(const visible of [4,5]) {
  const buckets=[0,0,0,0];buckets[field]=value;
  const old=verdict(rule,buckets,visible,false),now=verdict(rule,buckets,visible,true);
  rows.push(`${idx},${rule},${field},${String(value).toLowerCase()},${visible},${old},${now}`);
  const key=`${old}/${now}`;counts[key]=(counts[key]||0)+1;idx++;
}
const sha256=createHash('sha256').update(rows.join('\n')+'\n').digest('hex');
if(idx!==160||sha256!=='20cd16d5de1d43823bc3c98445eb29b7e3d0b36db61954056edecde037c87c33')throw Error('matrix mismatch');
if(verdict(2,[0,0,1,0],5,false)!==4||verdict(2,[0,0,1,0],5,true)!==3)throw Error('lower only');
if(verdict(0,[1,0,0,0],4,false)!==3||verdict(0,[1,0,0,0],4,true)!==2)throw Error('cardinality');
console.log(JSON.stringify({cases:idx,sha256,legacy_vs_hardened:counts}));
