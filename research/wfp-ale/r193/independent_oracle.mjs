// Independent R193 JavaScript oracle, no Python imports, network or WFP calls.
const cols=['family','tcp','redirected','not_reauth','identity_matches',
 'endpoint_matches','destination_matches','target_pid_matches','route_ready','history'];
console.log([...cols,'source_model_decision'].join(','));
for(const family of [4,6]){
 for(let n=0;n<256;n++){
  // itertools.product((0,1), repeat=8): first bit is most significant.
  const bits=Array.from({length:8},(_,i)=>(n >> (7-i))&1);
  const permit=bits.every(x=>x===1);
  for(const history of ['flowbridge','foreign_same_metadata']){
   const decision=permit?'PERMIT_CANDIDATE_NO_PROVIDER_PROOF':'DENY_OR_NOT_ATTESTED';
   console.log([family,...bits,history,decision].join(','));
  }
 }
}
