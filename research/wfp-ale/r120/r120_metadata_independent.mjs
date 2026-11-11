// Independent, dependency-free offline oracle. Does NOT read Windows/BFE.
import {createHash} from 'node:crypto';
const required = new Set(['PROCESS_ID','TRANSPORT_ENDPOINT_HANDLE','LOCAL_REDIRECT_TARGET_PID','ORIGINAL_DESTINATION']);
const all = [...required];
const table = new Set(['PROCESS_ID','TRANSPORT_ENDPOINT_HANDLE']);
function decision(bits,r,a,l,t,e,id,proto) {
  const available = new Set(all.filter((_,i)=>(bits & (1 << i))!==0));
  for(const fld of required) if(!available.has(fld)) return 0;
  return Number(r===1 && a===0 && l===1 && t===1 && e===1 && id===1 && proto===6);
}
const lines=[]; let admitted=0;
for(const family of [4,6]) for(let mask=0;mask<16;mask++)
for(const redirect of [0,1]) for(const reauth of [0,1])
for(const lease of [0,1]) for(const ticket of [0,1])
for(const epoch of [0,1]) for(const appid of [0,1])
for(const proto of [6,17]) {
  const v=decision(mask,redirect,reauth,lease,ticket,epoch,appid,proto); admitted+=v;
  lines.push([family,mask,redirect,reauth,lease,ticket,epoch,appid,proto,v].join(','));
}
const digest=createHash('sha256').update(lines.join('\n')+'\n').digest('hex');
if(lines.length!==4096 || admitted!==2 || table.size!==2 || decision(3,1,0,1,1,1,1,6)!==0) process.exit(3);
console.log(JSON.stringify({cases:lines.length,synthetic_admissible:admitted,rejected:lines.length-admitted,
  table_mask:3, required_mask:15,table_admissible:0,matrix_sha256:digest,
  source_level_only:true,native_wfp_observed:false}));
