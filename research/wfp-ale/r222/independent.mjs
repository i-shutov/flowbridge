// R222 independent age-domain oracle. No OS, socket or Windows APIs.
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const L=30000000,T=100000000, rows=[];
let late=0, lost=0;
for (const f of [4,6]) for (const a of [0,L-1,L,L+1]) for (const b of [0,T-1,T,T+1]) {
 for (const d of [0,1,2]) for (const p of [0,1]) {
  if(p && (d<1 || a>=L)) continue;
  // Independent formulation: time relative to heartbeat and issuance.
  const leaseAge=p ? -1 : a;
  const actualLeaseAge=leaseAge+d;
  const old=leaseAge<0 || leaseAge>L ? 0 : b>T ? 1 : 2;
  const fresh=actualLeaseAge<0 || actualLeaseAge>L ? 0 : b+d>T ? 1 : 2;
  if(old===2 && fresh!==2) late++;
  if(old===0 && fresh===2) lost++;
  rows.push([f,a,b,d,p,old,fresh].join(','));
 }
}
for(const f of [4,6]) {
 assert(rows.includes([f,L,0,1,0,2,0].join(',')));
 assert(rows.includes([f,0,T,1,0,2,1].join(',')));
 assert(rows.includes([f,0,0,1,1,0,2].join(',')));
 assert(rows.includes([f,L,T,0,0,2,2].join(',')));
 assert(rows.includes([f,L+1,0,0,0,0,0].join(',')));
}
assert(late>0 && lost>0);
console.log(`rows=${rows.length} late_admission=${late} false_terminal_loss=${lost} sha256=${createHash('sha256').update(rows.join('\n')+'\n').digest('hex')}`);
