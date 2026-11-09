// Independent enumeration; no OS, socket, network or WFP calls.
import {createHash} from 'node:crypto';
const rows=[];
for(const ip of ['v4','v6']) for(const h of [0,1]) for(const w of [0,1,32])
 for(const live of [0,1]) for(const barrier of [0,1]) for(const close of [0,1])
  for(const loss of ['healthy','ssh','bfe']) {
   let a,b,c;
   if(loss==='bfe') a=b=c='BFE_NO_PROOF';
   else {
    if(!h) a='HEARTBEAT_JOIN_STALLED';
    else if(w) a='WORKER_JOIN_STALLED';
    else if(!close) a='CLOSE_UNACKED';
    else if(live&&!barrier) a='CLOSED_WITH_GAP';
    else a='CONDITIONAL_ONLY';
    if(!close) b='CLOSE_UNACKED';
    else if(live&&!barrier) b='CLOSED_WITH_GAP';
    else if(!h||w) b='CLOSED_WORKERS_LIVE';
    else b='CONDITIONAL_ONLY';
    if(live&&!barrier) c='HOLD_NO_BARRIER';
    else if(!close) c='CLOSE_UNACKED';
    else if(!h||w) c='CLOSED_WORKERS_LIVE';
    else c='CONDITIONAL_ONLY';
   }
   rows.push([ip,h,w,live,barrier,close,loss,a,b,c]);
  }
const hash=createHash('sha256').update(rows.map(r=>JSON.stringify(r)+'\n').join('')).digest('hex');
console.log(JSON.stringify({states:rows.length,sha256:hash}));
