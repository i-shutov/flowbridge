/* R113 independent Node oracle; no Windows/BFE/network operations. */
import { createHash } from 'node:crypto';
const labels=['auth_connect_v4','auth_connect_v6','connect_redirect_v4','connect_redirect_v6'];
const statuses=['VISIBLE_ARBITRATION_CANDIDATE','UNKNOWN_NO_VISIBLE_CANDIDATE','UNKNOWN'];
function rows(hi,eq,status,proof){
 let out=labels.map((name,i)=>({rule:name,visible_higher:i===0?hi:0,visible_equal:i===1?eq:0,visible_lower:0,visible_disabled:0,match_and_runtime_action_unverified:true}));
 out.push({status,single_enum_snapshot:true,acl_hidden_filters_possible:true,kernel_proof:proof,no_direct_proof:false,visible_filters:4});return out;
}
function check(code,data){
 const failed={status:'UNAVAILABLE_OR_FAILED',exit_code:2};
 if(code!==3&&code!==4)return failed;
 if(data.length!==5)return failed;
 let candidate=false;
 for(let i=0;i<4;i++){
   const x=data[i];
   if(x.rule!==labels[i]||x.match_and_runtime_action_unverified!==true)return failed;
   for(const k of ['visible_higher','visible_equal','visible_lower','visible_disabled']) {
     if(!Number.isInteger(x[k])||x[k]<0)return failed;
   }
   candidate ||= x.visible_higher>0 || x.visible_equal>0;
 }
 const t=data[4],want=candidate?'VISIBLE_ARBITRATION_CANDIDATE':'UNKNOWN_NO_VISIBLE_CANDIDATE',rc=candidate?3:4;
 if(code!==rc||t.status!==want||t.single_enum_snapshot!==true||t.acl_hidden_filters_possible!==true||
    t.kernel_proof!==false||t.no_direct_proof!==false)return failed;
 return {status:candidate?'BFE_VISIBLE_ARBITRATION_CANDIDATE_NO_KERNEL_PROOF':'BFE_UNKNOWN_NO_VISIBLE_CANDIDATE',exit_code:rc};
}
let data=[];
for(let code=0;code<6;code++)for(let hi=0;hi<2;hi++)for(let eq=0;eq<2;eq++)for(const term of statuses)for(const proof of [false,true]) {
 const res=check(code,rows(hi,eq,term,proof));
 data.push({case:`${code}:${hi}:${eq}:${term}:${Number(proof)}`,status:res.status,exit_code:res.exit_code});
}
for(const mutation of ['missing_row','wrong_rule','missing_counter','negative_counter','proof_claimed','hidden_acl_false','nonbool_counter','duplicated_rule','missing_terminal','no_direct_true']) {
 let r=rows(1,0,statuses[0],false);
 switch(mutation){
  case 'missing_row':r.shift();break;
  case 'wrong_rule':r[2].rule='connect_redirect_v7';break;
  case 'missing_counter':delete r[1].visible_higher;break;
  case 'negative_counter':r[0].visible_lower=-3;break;
  case 'proof_claimed':r[4].kernel_proof=true;break;
  case 'hidden_acl_false':r[4].acl_hidden_filters_possible=false;break;
  case 'nonbool_counter':r[0].visible_lower=false;break;
  case 'duplicated_rule':r[0].rule=r[1].rule;break;
  case 'missing_terminal':r.pop();break;
  case 'no_direct_true':r[4].no_direct_proof=true;break;
 }
 const res=check(3,r);data.push({case:'mutation:'+mutation,status:res.status,exit_code:res.exit_code});
}
// Python writes keys sorted lexicographically. Preserve that exact canonical byte format.
const lines=data.map(({case:c,status,exit_code})=>JSON.stringify({case:c,exit_code,status})+'\n').join('');
const summary={cases:data.length,sha256:createHash('sha256').update(lines).digest('hex'),
 statuses:Object.fromEntries([...new Set(data.map(x=>x.status))].sort().map(k=>[k,data.filter(x=>x.status===k).length]))};
console.log(JSON.stringify(summary));
