// R81 independent loop. No OS, network, filter or driver calls.
import {createHash} from 'node:crypto';
let n=0,counts={},hash=createHash('sha256');
for(const ip of [4,6]) for(const proto of [6,17,1,58])
for(const alive of [0,1]) for(const close of ['none','ok','error'])
for(const barrier of [0,1]) for(const future of [0,1])
for(const pending of [0,1,32]) for(const bfe of [0,1]) for(const ssh of [0,1]) {
 const scope=proto!==6?'NOT_MATCHED_BY_R19':'TCP_CANDIDATE';
 let session;
 if(alive===0||close==='ok')session='DYNAMIC_SESSION_ENDED';
 else if(close==='error')session='CLOSE_OUTCOME_UNKNOWN';
 else if(bfe===0)session='BFE_UNVERIFIED';
 else session='SESSION_OPEN_MODELED';
 const reached=+(pending===0),lost=+(alive===1&&close==='error');
 const unsafe=scope!=='TCP_CANDIDATE'||session!=='SESSION_OPEN_MODELED';
 const unguarded=+(future===1&&barrier===0&&unsafe);
 const row=[ip,proto,alive,close,barrier,future,pending,bfe,ssh,scope,session,reached,lost,unguarded];
 hash.update(row.join('|')+'\n');n++;
 for(const k of [scope,session])counts[k]=(counts[k]||0)+1;
 for(const [k,v] of [['CLOSE_REACHABLE',reached],['LOST_HANDLE',lost],['UNGUARDED_CASE',unguarded]])if(v)counts[k]=(counts[k]||0)+1;
}
console.log(JSON.stringify({total:n,sha256:hash.digest('hex'),counts:Object.fromEntries(Object.entries(counts).sort())}));
