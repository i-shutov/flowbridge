// Independent JS oracle enumerating linear positions, never imports Python/Rust.
import {createHash} from 'node:crypto';
const rights=[0,1,2,3,256,257,4294967295], actions=[0,17,18,38,7,4660];
let total=0,blocks=0,preserved=0;const h=createHash('sha256');
for(let k=0;k<rights.length*actions.length;k++){
  const r=rights[Math.floor(k/6)],a=actions[k%6];
  const permitted=Boolean((r&1)!==0||a===18);
  const nextRights=permitted?(r & 0xfffffffe):r;
  const nextAction=permitted?17:a;
  h.update(`${r}:${a}:${Number(permitted)}:${nextRights>>>0}:${nextAction}\n`,'ascii');
  total++;if(permitted)blocks++;else preserved++;
}
console.log(JSON.stringify({states:total,blocks,preserved,sha256:h.digest('hex')}));
