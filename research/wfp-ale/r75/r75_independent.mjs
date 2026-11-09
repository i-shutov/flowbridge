// Independent Node.js R75 oracle; no Windows, kernel or network calls.
import {createHash} from 'node:crypto';
let H=createHash('sha256'),C={total:0,identical_observation_pairs:0,selected_lost_event:0,unrelated_event_stop:0,fixed_size_fit:0,bounded_size_fit:0,size_recoverable:0,v4:0,v6:0};
for(let f of [4,6])for(let o of ['selected','foreign'])for(let e of ['absent','authenticated','replay','wrong_epoch','spoofed'])for(let n of [0,1,65536,65537,1048576,1048577])for(let s of [0,1])for(let p of [0,1])for(let t of [0,1]){
  let a=Number(s===1&&n>0&&n<=65536),b=Number(s===1&&n>0&&n<=1048576);
  let d=e==='authenticated'?'KERNEL_EVENT_STOP':'SOCKET_DROP';
  H.update([f,o,e,n,s,p,t,d,a,b].join('|')+'\n');C.total++;C['v'+f]++;
  C.fixed_size_fit+=a;C.bounded_size_fit+=b;C.size_recoverable+=Number(b===1&&a===0);
  C.selected_lost_event+=Number(o==='selected'&&e==='absent');
  C.unrelated_event_stop+=Number(o==='foreign'&&e==='authenticated');
}
C.identical_observation_pairs=C.total/2;C.sha256=H.digest('hex');
if(C.total!==960||C.v4!==480||C.v6!==480)throw Error('matrix cardinality');
console.log(JSON.stringify(C));
