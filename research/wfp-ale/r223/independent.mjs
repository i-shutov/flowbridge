// R223: independent age-domain oracle, no OS/Windows/network calls.
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const L=30_000_000,T=100_000_000,rows=[];
const classify=(pingAge,claimLeaseAge,ticketAge)=>
    pingAge>L || claimLeaseAge>L ? 0 : ticketAge>T ? 1 : 2;
for(const f of [4,6]) for(const a of [L-10000,L-1,L,L+1])
for(const d of [0,1,2,10000,20000]) for(const lag of [0,1,10000,L])
for(const age of [0,L,T-1,T,T+1]) {
    const old=classify(a,d,age+d);
    const claimFixed=classify(a,d+lag,age+d+lag);
    const pingFixed=classify(a+d,0,age+d);
    const bothFixed=classify(a+d,lag,age+d+lag);
    rows.push([f,a,d,lag,age,old,claimFixed,pingFixed,bothFixed]);
}
const witnesses=rows.filter(r=>r[1]<=L && r[1]+r[2]>L && r[6]===2 && r[8]===0);
for(const f of [4,6]) {
    for(const expected of [[f,L,10000,10000,L,2,2,0,0],[f,L-10000,20000,10000,L,2,2,0,0],[f,L,0,0,0,2,2,2,2],[f,L+1,0,0,0,0,0,0,0],[f,L,10000,L,0,2,0,0,0]])
        assert(rows.some(r=>r.every((v,i)=>v===expected[i])));
}
assert(witnesses.length>0 && witnesses.every(r=>r[7]===0));
assert(rows.filter(r=>r[1]+r[2]>L).every(r=>r[8]===0));
const data=rows.map(r=>r.join(',')+'\n').join('');
console.log(`rows=${rows.length} fresh_claim_only_late_renewal=${witnesses.length} sha256=${createHash('sha256').update(data).digest('hex')}`);
