// Independent JavaScript oracle: same input ordering, separate predicate.
// Read-only pure computation; no dependency on Python or Rust runtime.
import {createHash} from 'node:crypto';
const order=[false,true];
const weights=[0x7000,0,0x6fff,0x7001,0xffff];
let row='', n=0, match=0, rejected=0;
for (const api of order) for (const found of order)
for (const key of order) for (const flags of order)
for (const provider of order) for (const weight of weights) {
  const observed=(api===true && found===true);
  const pristine=(key && flags && provider && weight===0x7000);
  const code=observed&&pristine?4:2;
  row+=n+','+code+'\n'; n++;
  if(code===4) match++; else rejected++;
}
if(n!==160 || match!==1 || rejected!==159) throw Error('independent matrix incorrect');
console.log(JSON.stringify({descriptor_only:match,sha256:createHash('sha256').update(row).digest('hex'),total:n,unknown:rejected}));
