// Independent fixed-index table traversal, no Python/Rust import or native API.
import {createHash} from 'node:crypto';
const expected=[[7,11],[7,0],[0,11],[0,0]],got=[[7,11],[8,11],[7,12],[8,12],[0,0]];
const waits=[[258,258],[0,0],[258,0],[0,258],[4294967295,4294967295],[128,128]];
const lines=[];let eligible=0,weak=0;
for(let index=0;index<480;index++){
  const app=index%2,code=[259,23][Math.floor(index/2)%2];
  const w=waits[Math.floor(index/4)%6],c=got[Math.floor(index/24)%5],e=expected[Math.floor(index/120)];
  const all=[e[0]!==0,e[1]!==0,e[0]===c[0],e[1]===c[1],w[0]===258,w[1]===258,code===259,app===1];
  const ok=Number(all.every(Boolean));eligible+=ok;weak+=app;
  lines.push(`${e[0]}:${e[1]}:${c[0]}:${c[1]}:${w[0]}:${w[1]}:${code}:${app}:${ok}\n`);
}
console.log(JSON.stringify({states:lines.length,eligible,appid_only_eligible:weak,sha256:createHash('sha256').update(lines.join(''),'ascii').digest('hex')}));
