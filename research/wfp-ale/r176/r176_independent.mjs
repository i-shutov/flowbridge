#!/usr/bin/env node
// Independent combinatorial oracle: no queue implementation and no R19 import.
function integers(n){return Array.from({length:n},(_,i)=>i+1)}
let count=0;
for(const family of [4,6]) for(let n=1;n<=5;n++){
  for(let reads=0;reads<=n;reads++) for(let persisted=0;persisted<=reads;persisted++){
    const all=integers(n);
    const durable=all.filter(x=>x<=persisted||x>reads);
    const missing=all.filter(x=>x>persisted&&x<=reads);
    const row={family,n,reads,persisted,durable,missing,empty:true,lost:false,
      tail_silent:missing.length>0&&missing[missing.length-1]===n};
    // Python sort_keys=True, so sort every key lexically.
    const sorted=Object.fromEntries(Object.keys(row).sort().map(k=>[k,row[k]]));
    console.log(JSON.stringify(sorted));count++;
  }
}
if(count!==110)throw Error('Expected 110 cases, got '+count);
