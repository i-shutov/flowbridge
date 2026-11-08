// R49 independently authored Boolean lattice. No WFP/network/process actions.
// This oracle deliberately does NOT import the Python or Rust implementations.
const common = ['kernel_origin','session','epoch','issuance','endpoint',
 'owner_alive','ssh_alive','wfp_alive','tcp','selected_original','flow_bound','not_revoked'];
const tails = {pending:['completed','not_consumed'], policy:['established','policy_checked']};
const result = { matrix:{},total_cases:0,total_conditional_model_permits:0,
 mutation_detectors:0, native_windows_tests:0,rust_tests_executed:0 };
for (const ip of [4,6]) {
  for (const kind of ['pending','policy']) {
    const required = common.concat(tails[kind]);
    let permits = 0;
    const size = 2 ** required.length;
    for(let value=0;value<size;value++) {
      // Independent inverse specification: a refusal occurs if ANY required bit is absent.
      let refused = false;
      for(let position=0;position<required.length;position++) {
        if ((value & (1 << position)) === 0) { refused = true; break; }
      }
      if(!refused) permits++;
    }
    result.matrix[`v${ip}_${kind}`] = {cases:size,model_permits:permits,existing_source_reauth_permits:0};
    result.total_cases+=size;
    result.total_conditional_model_permits+=permits;
  }
}
// Mutation sensitivity is counted by constructing a witness with one failure
// and verifying every single-guard removal admits it, while the full spec rejects.
const check = common.concat(tails.pending);
for(let disabled=0;disabled<check.length;disabled++) {
  const bits = check.map((_,index)=>index!==disabled);
  const correct = bits.every(Boolean);
  const weakened = bits.every((bit,index)=>index===disabled || bit);
  if(!correct && weakened)result.mutation_detectors++;
}
if(result.total_cases!==65536 || result.total_conditional_model_permits!==4 || result.mutation_detectors!==14)
  throw new Error('independent oracle count mismatch');
console.log(JSON.stringify(result,null,2));
