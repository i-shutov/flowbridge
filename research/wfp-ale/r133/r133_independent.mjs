// Independent table arithmetic, not a Python/Rust import.
import {createHash} from 'node:crypto';
const waits=[0,258,128,4294967295,1,999],codes=[0,23,259,4294967295,1];
const rows=[];
for(let n=0;n<60;n++){
 const w=waits[Math.floor(n/10)],c=codes[Math.floor(n/2)%5],ok=n%2;
 let state='EXIT_QUERY_ERROR';
 if(ok) state=w===0?'EXITED':w!==258?'UNKNOWN_WAIT':c===259?'NOT_SIGNALED_AT_READ':'RACED_OR_INCONSISTENT';
 rows.push(`${w}:${c}:${ok}:${state}\n`);
}
console.log(JSON.stringify({states:rows.length,sha256:createHash('sha256').update(rows.join(''),'ascii').digest('hex'),terminated_259:'EXITED',naive_exit_only_alive_259:true}));
