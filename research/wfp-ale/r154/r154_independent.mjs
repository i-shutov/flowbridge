// Independent JavaScript classifier: no filesystem, Windows, WFP or Python imports.
import {createHash} from 'node:crypto';
const stats = {COMPARTMENT_UNBOUND_CONDITIONAL:0,MATCHED_MODEL_ONLY:0,OTHER_REQUIRED_FIELD_REJECTED:0};
const sha = createHash('sha256');
let states=0;
for(const family of [4,6])for(const live of [0,1])for(const epoch of [0,1])
for(const endpoint of [0,1])for(const comp of ['equal','different','missing'])
for(const app of [0,1])for(const right of [0,1]){
  // This oracle is written independently of the Python function.
  let outcome='OTHER_REQUIRED_FIELD_REJECTED';
  if (live+epoch+endpoint+app+right===5)
    outcome=comp==='equal'?'MATCHED_MODEL_ONLY':'COMPARTMENT_UNBOUND_CONDITIONAL';
  stats[outcome]++;
  sha.update([family,live,epoch,endpoint,comp,app,right,outcome].join('|')+'\n','ascii');
  states++;
}
if(states!==192 || stats.COMPARTMENT_UNBOUND_CONDITIONAL!==4 ||
   stats.MATCHED_MODEL_ONLY!==2 || stats.OTHER_REQUIRED_FIELD_REJECTED!==186)
  throw Error('INDEPENDENT_ORACLE_INVARIANT_FAILED');
console.log(JSON.stringify({states,categories:stats,sha256:sha.digest('hex'),
  compartment_evidence_proved:false,native_wfp_executed:false,
  endpoint_reuse_observed:false,release_accepted:false}));
