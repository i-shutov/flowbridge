// R191 independent JavaScript oracle. Explicit decision table; does not import Python.
const L=['family,bfe,protocol,app,attested,relative,foreign,layer,r19_hard,soft_counterfactual,classification'];
for(const family of ['v4','v6'])for(const bfe of [false,true])
for(const protocol of ['tcp','udp'])for(const app of ['selected','sibling'])
for(const attested of [false,true])for(const relative of ['higher','lower'])
for(const foreign of ['none','block','veto','permit'])for(const layer of ['same','other']){
  let hard,soft;
  if(!bfe) hard=soft='UNKNOWN_BFE_LOSS';
  else if(protocol==='udp'||app==='sibling') hard=soft='OUT_OF_SCOPE';
  else if(!attested) hard=soft='BLOCK_R19_AUTH';
  else if(foreign==='none'||foreign==='permit') hard=soft='PERMIT_MODEL';
  else if(layer==='other') hard=soft='BLOCK_OTHER_LAYER';
  else if(relative==='higher') hard=soft='BLOCK_HIGHER_SUBLAYER';
  else if(foreign==='veto') hard=soft='BLOCK_VETO';
  else if(foreign==='block'){
    hard='PERMIT_HARD_OVERRIDES_LOW_BLOCK';soft='BLOCK_SOFT_LOW_BLOCK';
  } else throw new Error('unexpected');
  L.push([family,Number(bfe),protocol,app,Number(attested),relative,foreign,layer,hard,soft,'CANDIDATE_NOT_NATIVE_PROOF'].join(','));
}
process.stdout.write(L.join('\n')+'\n');
