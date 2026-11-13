// Independently written model of the documented CALLOUT_UNKNOWN result.
// Source-level counterexample only; no WFP, network or source modification.
import {createHash} from 'node:crypto';
const states=['SELF','PREVIOUS_SELF'];
const actions=['BLOCK','PERMIT','CONTINUE','NONE'];
const hash=createHash('sha256');
const count={SELF_RETURN_UNSET:0,PREVIOUS_SELF_UNSET:0,INHERITED_PERMIT:0,INHERITED_BLOCK:0,INHERITED_CONTINUE:0,UNSPECIFIED:0};
let n=0;
for(const family of [4,6]){
  for(const state of states){
    for(const action of actions){
      for(const write of [0,1]){
        const tag=state==='SELF'?'SELF_RETURN_UNSET':'PREVIOUS_SELF_UNSET';
        const effect=action==='NONE'?'UNSPECIFIED':action;
        count[tag]++;
        count[effect==='UNSPECIFIED'?'UNSPECIFIED':'INHERITED_'+effect]++;
        hash.update([family,state,action,write,tag,effect].join('|')+'\n','ascii');
        n++;
      }
    }
  }
}
if(n!==32||count.SELF_RETURN_UNSET!==16||count.PREVIOUS_SELF_UNSET!==16||count.INHERITED_PERMIT!==8||count.INHERITED_BLOCK!==8||count.INHERITED_CONTINUE!==8||count.UNSPECIFIED!==8)
  throw Error('matrix failure');
console.log(JSON.stringify({states:n,categories:count,sha256:hash.digest('hex'),source_is_runtime_proof:false,native_wfp_executed:false,release_accepted:false}));
