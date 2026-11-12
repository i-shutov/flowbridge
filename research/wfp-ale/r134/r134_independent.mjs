// Independent required-condition set, no Python/Rust import.
import {createHash} from 'node:crypto';
const rows=[]; let ok=0;
for(let m=0;m<256;m++) {
  const observed=new Set();
  for(let n=m,index=0;index<8;index++,n=Math.floor(n/2))if(n%2)observed.add(index);
  let exit=0;
  for(const required of [0,1,2,3,4,5,6])if(!observed.has(required))exit=3;
  if(exit===0)ok++;
  rows.push(`${String(m).padStart(3,'0')}:${exit}\n`);
}
console.log(JSON.stringify({states:rows.length,consistent:ok,sha256:createHash('sha256').update(rows.join(''),'ascii').digest('hex')}));
