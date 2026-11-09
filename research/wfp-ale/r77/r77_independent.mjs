// Independently implemented synthetic oracle; never performs I/O other than stdout.
import {createHash} from 'node:crypto';
const cap=65536, limit=1048576;
const states=['SUCCESS','INSUFFICIENT','EINVAL','NOTCONN','PENDING','UNSUPPORTED','NETDOWN'];
const required=[0,4,cap,cap+1,limit,limit+1];
const lengths=[0,4,cap,cap+1];
const followups=['SUCCESS','INSUFFICIENT','EINVAL','PENDING','SOCKET_SWAP'];
const counts=new Map(), hash=createHash('sha256');
let cases=0;
for (const family of [4,6]) for (const status of states)
 for (const need of required) for (const read of lengths)
 for (const owned of [false,true]) for (const goodContext of [false,true])
 for (const retry of followups) {
   let answer;
   if (!owned) answer='REJECT_DIFFERENT_SOCKET';
   else if (!goodContext) answer='REJECT_BAD_CONTEXT';
   else if (status==='SUCCESS') answer=read>=1 && read<=cap ? 'CANDIDATE_NOT_PROOF' : 'REJECT_BAD_LENGTH';
   else if (status!=='INSUFFICIENT') answer='REJECT_UNVERIFIABLE_ERROR';
   else if (need<=cap || need>limit) answer='REJECT_INVALID_REQUIRED_LENGTH';
   else if (retry==='SOCKET_SWAP') answer='REJECT_DIFFERENT_SOCKET';
   else if (retry!=='SUCCESS') answer='REJECT_RETRY_FAILED';
   else answer=read>=1 && read<=need ? 'CANDIDATE_NOT_PROOF':'REJECT_BAD_LENGTH';
   counts.set(answer, (counts.get(answer)||0)+1);
   hash.update(answer+'\n'); cases++;
 }
const sorted=Object.fromEntries([...counts.entries()].sort(([a],[b])=>a.localeCompare(b,'en')));
console.log(JSON.stringify({cases,counts:sorted,sha256:hash.digest('hex')}));
