// Independent boolean set oracle, not imported from Rust/Python.
import {createHash} from 'node:crypto';
const lines=[];let pass=0;
for(let mask=0;mask<256;mask++) {
  const bits=new Set();
  for(let bit=0;bit<8;bit++)if(Math.floor(mask/(2**bit))%2===1)bits.add(bit);
  let ok=true;for(const needed of [0,1,2,3,4,5,6])if(!bits.has(needed))ok=false;
  const code=ok?0:3;if(ok)pass++;
  lines.push(`${String(mask).padStart(3,'0')}:${code}\n`);
}
console.log(JSON.stringify({states:lines.length,consistent:pass,sha256:createHash('sha256').update(lines.join(''),'ascii').digest('hex')}));
