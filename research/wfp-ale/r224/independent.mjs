// R224: age-domain algebra independent of Python absolute-time state machine.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const L=30000000,T=100000000,rows=[];
for(const f of [4,6]) for(const age of [0,L-10000,L-1,L,L+1])
for(const lag of [0,1,10000,20000]) for(const ticket of [0,T-10000,T-1,T,T+1])
for(const gap of [0,1,10000,L]){
  const leaseS=age<=L,leaseA=age+lag<=L,leaseQ=age+lag+gap<=L;
  const ticketS=ticket<=T,ticketA=ticket+lag<=T,ticketQ=ticket+lag+gap<=T;
  const old=leaseS&&ticketA,first=leaseS&&ticketS,last=leaseA&&ticketA;
  const finish=leaseQ&&ticketQ;
  assert(!old||first);
  assert(!finish||old&&first&&last);
  rows.push([f,age,lag,ticket,gap,+old,+!leaseS,+(old&&finish),+first,+!leaseS,+(first&&finish),+last,+!leaseA,+(last&&finish)]);
}
const late=rows.filter(r=>r[5]&&!r[11]).length;
const early=rows.filter(r=>r[8]&&!r[5]).length;
assert(late&&early);
assert(rows.every(r=>r[7]===r[10]&&r[10]===r[13]));
console.log(`rows=${rows.length} late_auth=${late} early_contract_reject=${early} claim_disagreements=0 sha256=${createHash('sha256').update(rows.map(r=>r.join(',')+'\n').join('')).digest('hex')}`);
