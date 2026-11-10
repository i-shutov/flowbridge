import {createHash} from 'node:crypto';
// Independent bit-packed enumeration; canonical CSV ordered lexicographically.
const n={total:0,old_pass:0,old_pass_no_coexistence:0,old_pass_with_coexistence:0,txn_pass:0};
const h=createHash('sha256');
for(let i=0;i<65536;i++){
  const a=(i>>>12)&15,b=(i>>>8)&15,c=(i>>>4)&15,d=i&15;
  const old=+((a&1)!==0&&(b&2)!==0&&(c&4)!==0&&(d&8)!==0);
  const co=+(a===15||b===15||c===15||d===15);
  const txn=+(a===15);
  n.total++;n.old_pass+=old;n.old_pass_no_coexistence+=old*(1-co);
  n.old_pass_with_coexistence+=old*co;n.txn_pass+=txn;
  h.update([a,b,c,d,old,co,txn].join(',')+'\n');
}
if(n.total!==65536||n.old_pass!==4096||n.old_pass_no_coexistence!==2401||n.old_pass_with_coexistence!==1695||n.txn_pass!==4096)throw Error('unexpected counterexample counts');
console.log(n);console.log(h.digest('hex'));
