/* R114 standalone Node oracle: independent of Python check(); no network/WFP. */
import {createHash} from 'node:crypto';
const max=131072, labels=['auth_connect_v4','auth_connect_v6','connect_redirect_v4','connect_redirect_v6'];
function make(hi,eq,bt,ct,vt){
 const parts=labels.map((name,i)=>({rule:name,visible_higher:i===0?hi:0,visible_equal:i===1?eq:0,visible_lower:0,visible_disabled:0,match_and_runtime_action_unverified:true}));
 const tail={status:hi||eq?'VISIBLE_ARBITRATION_CANDIDATE':'UNKNOWN_NO_VISIBLE_CANDIDATE',single_enum_snapshot:true,acl_hidden_filters_possible:true,kernel_proof:false,no_direct_proof:false,visible_filters:4+hi+eq};
 if(bt==='numeric'){tail.kernel_proof=0;parts[0].match_and_runtime_action_unverified=1;}
 else if(bt==='strings'){tail.single_enum_snapshot='true';parts[0].match_and_runtime_action_unverified='true';}
 if(ct==='fraction')parts[0].visible_higher=hi+0.5;
 else if(ct==='boolean')parts[0].visible_higher=true;
 else if(ct==='negative')parts[0].visible_lower=-1;
 else if(ct==='overbudget')parts[0].visible_lower=max+1;
 if(vt==='too_small')tail.visible_filters=4+hi+eq-1;
 else if(vt==='missing')delete tail.visible_filters;
 else if(vt==='boolean')tail.visible_filters=true;
 else if(vt==='overbudget')tail.visible_filters=max+1;
 return [...parts,tail];
}
function judge(rc,data){
 const fail=['UNAVAILABLE_OR_FAILED',2];
 if((rc!==3&&rc!==4)||data.length!==5)return fail;
 let count=0,flag=false;
 for(let n=0;n<4;n++){
  const line=data[n];
  if(line.rule!==labels[n]||line.match_and_runtime_action_unverified!==true)return fail;
  for(const key of ['visible_higher','visible_equal','visible_lower','visible_disabled']) {
   const val=line[key];if(typeof val!=='number'||!Number.isInteger(val)||val<0||val>max)return fail;
   count+=val;
  }
  flag=flag||line.visible_higher>0||line.visible_equal>0;
 }
 const last=data[4];
 if(typeof last.visible_filters!=='number'||!Number.isInteger(last.visible_filters)||last.visible_filters<4||last.visible_filters>max||count>last.visible_filters-4)return fail;
 for(const [key,truth] of [['single_enum_snapshot',true],['acl_hidden_filters_possible',true],['kernel_proof',false],['no_direct_proof',false]]){
   if(typeof last[key]!=='boolean'||last[key]!==truth)return fail;
 }
 const want=flag?'VISIBLE_ARBITRATION_CANDIDATE':'UNKNOWN_NO_VISIBLE_CANDIDATE',exit=flag?3:4;
 if(last.status!==want||rc!==exit)return fail;
 return [flag?'BFE_VISIBLE_ARBITRATION_CANDIDATE_NO_KERNEL_PROOF':'BFE_UNKNOWN_NO_VISIBLE_CANDIDATE',exit];
}
let items=[];
for(let rc=0;rc<6;rc++)for(let hi=0;hi<2;hi++)for(let eq=0;eq<2;eq++)for(const bt of ['valid','numeric','strings'])for(const ct of ['valid','fraction','boolean','negative','overbudget'])for(const vt of ['valid','too_small','missing','boolean','overbudget']) {
 const [status,exit_code]=judge(rc,make(hi,eq,bt,ct,vt));
 items.push({case:[rc,hi,eq,bt,ct,vt].join(':'),status,exit_code});
}
const serialized=items.map(({case:c,exit_code,status})=>JSON.stringify({case:c,exit_code,status})+'\n').join('');
const keys=[...new Set(items.map(x=>x.status))].sort();
console.log(JSON.stringify({cases:items.length,sha256:createHash('sha256').update(serialized).digest('hex'),statuses:Object.fromEntries(keys.map(k=>[k,items.filter(r=>r.status===k).length]))}));
