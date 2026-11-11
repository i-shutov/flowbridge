// Independent Node enumeration, offline: never a WFP/kernel proof.
import {createHash} from 'node:crypto';
const A=[0,64,32,96,16,1,8,128],B=[0,64,32,96,16,1,128],W=[-1,0,1];
const x={cases:0,old_candidates:0,corrected_candidates:0,false_old_candidates:0,
 disabled_foreign_active_owner:0,bad_owned_flags:0,absent_owned:0};
const digest=createHash('sha256');
for(let r=0;r<4;r++)for(let v=0;v<2;v++)for(const a of A)for(const b of B)for(const w of W){
 const old=!v?'UNKNOWN_OWNED_NOT_VISIBLE':w>=0?'VISIBLE_ARBITRATION_CANDIDATE':'UNKNOWN_NO_ACTIVE_COMPETITOR';
 let now='UNKNOWN_NO_ACTIVE_COMPETITOR';
 if(!v)now='UNKNOWN_OWNED_NOT_VISIBLE';
 else if(a!==0&&a!==64)now='UNKNOWN_OWNED_FLAGS';
 else if(b===32||b===96)now='UNKNOWN_NO_ACTIVE_COMPETITOR';
 else if(w>=0)now='VISIBLE_ARBITRATION_CANDIDATE';
 const before=old==='VISIBLE_ARBITRATION_CANDIDATE',after=now==='VISIBLE_ARBITRATION_CANDIDATE';
 x.cases++;x.old_candidates+=Number(before);x.corrected_candidates+=Number(after);
 x.false_old_candidates+=Number(before&&!after);
 x.disabled_foreign_active_owner+=Number(v===1&&(a===0||a===64)&&(b===32||b===96));
 x.bad_owned_flags+=Number(v===1&&a!==0&&a!==64);x.absent_owned+=Number(v===0);
 digest.update(`${r}|${v}|${a}|${b}|${w}|${old}|${now}\n`);
}
x.unsafe_permits=0;x.decision_sha256=digest.digest('hex');
x.native_windows_executed=false;x.kernel_origin_proof=false;
if(x.cases!==1344||x.old_candidates!==448||x.corrected_candidates!==80||x.false_old_candidates!==368)throw Error('R111 drift');
console.log(JSON.stringify(Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b)))));
