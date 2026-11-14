// R177 independent closed-form oracle; intentionally does not simulate Kernel/Worker.
import assert from 'node:assert/strict';

const stages = ['before-peek','after-peek','after-first','after-second'];
const orders = ['persist-ack','ack-persist'];
let total=0, failures=0, tail=0;
for (const family of [4,6]) {
  for (const ordering of orders) {
    for (let n=1;n<=4;n++) {
      for (let cut=1;cut<=n;cut++) {
        for (const stage of stages) {
          // A destructive ACK prior to an uncommitted first journal write
          // erases exactly the cut-th record. All other cuts are replayable.
          const missing = ordering === 'ack-persist' && stage === 'after-first' ? [cut] : [];
          const durable = Array.from({length:n},(_,i)=>i+1).filter(x=>!missing.includes(x));
          const row={cut,durable,empty:true,family,lost:false,missing,n,ordering,stage,
                     tail_silent:missing.includes(n)};
          console.log(JSON.stringify(row));
          total++;if(missing.length)failures++;if(row.tail_silent)tail++;
        }
      }
    }
  }
}
assert.equal(total,160);
assert.equal(failures,20);
assert.equal(tail,8);
// Independent token-authorization truth table: session, exact reader object,
// transaction, generation, head receipt, monotonic deadline all required.
const base={session:104,reader:'pid707:epoch1700:canonicalExeA',receipt:1,tx:5001,generation:1,now:3,deadline:5};
const authorize=(p)=>p.session===104 && p.reader===base.reader && p.receipt===1 &&
  p.tx===5001 && p.generation===1 && p.now < p.deadline;
assert.equal(authorize(base),true);
for(const wrong of [{session:105},{reader:'pid707:epoch1701:canonicalExeA'},
  {receipt:2},{tx:9999},{generation:2},{now:5},{now:6}]){
  assert.equal(authorize({...base,...wrong}),false,JSON.stringify(wrong));
}
