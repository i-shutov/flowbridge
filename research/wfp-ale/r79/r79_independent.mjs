// Independent R79 event/state oracle. Node built-ins only, zero sockets or WFP.
import {createHash} from 'node:crypto';
const hash=createHash('sha256'), totals={};
let cases=0, premature=0;
for(const family of [4,6])for(const state of ['PENDING','COMPLETED','CANCELLED','FAILED'])
for(const expired of [0,1])for(const cancel of [0,1])
for(const socket of [0,1])for(const epoch of [0,1])for(const ctx of [0,1]){
  const incomplete=state==='PENDING';
  const label=incomplete?'HOLD_PENDING':
    state!=='COMPLETED'?'REJECT_TERMINAL':
    expired?'REJECT_LATE':
    (!socket||!epoch||!ctx)?'REJECT_CONTEXT':'CONDITIONAL_RECEIPT_NOT_PROOF';
  const retained=Number(incomplete);
  const candidate=Number(label==='CONDITIONAL_RECEIPT_NOT_PROOF');
  if(incomplete&&expired)premature++;
  totals[label]=(totals[label]||0)+1;cases++;
  hash.update([family,state,expired,cancel,socket,epoch,ctx].join(',')+'|'+label+'|'+retained+'|'+candidate+'\n');
}
console.log(JSON.stringify({cases,outcomes:totals,naive_release_while_pending:premature,sha256:hash.digest('hex')}));
