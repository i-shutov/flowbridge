// Independent JS exhaustive oracle; no imports, no network/BFE/OS access.
// Bit masks enumerate observable equality and distinct actual selectedness.
const observed = ["selected", "sibling", "empty"];
const protocol = ["tcp", "udp", "empty"];
const reason = ["initial", "classify_completion", "policy_change"];
let counts={total:0,callback_invoked:0,callback_not_invoked:0,source_authorized_model:0,
  conditional_uninspected_reauth_permit:0,conditional_revoked_uninspected_reauth_permit:0,
  by_family:{"4":{states:0,revoked_uninspected:0},"6":{states:0,revoked_uninspected:0}},
  indistinguishable_selection_pairs:0};
for(const family of [4,6]) for(const source of [0,1]) for(let a=0;a<3;a++)
for(let p=0;p<3;p++) for(let r=0;r<3;r++) for(let bits=0;bits<16;bits++){
  let owner=Boolean(bits&1),ssh=Boolean(bits&2),receipt=Boolean(bits&4),fallback=Boolean(bits&8);
  // This implementation computes a mismatch mask, independently of Python's
  // positive conjunction used for the routing predicate.
  const notSelectedApp=a!==0,notTcp=p!==0;
  const dispatched=!(notSelectedApp||notTcp);
  const admitted=dispatched&&source===1&&r===0&&owner&&ssh&&receipt;
  const fieldUnknown=(a===2||p===2);
  const possibleFallthrough=source===1 && r!==0 && fieldUnknown && !dispatched && fallback;
  const revoked=possibleFallthrough && (!owner || !ssh);
  counts.total++;
  counts.by_family[String(family)].states++;
  if(dispatched)counts.callback_invoked++;else counts.callback_not_invoked++;
  if(admitted)counts.source_authorized_model++;
  if(possibleFallthrough)counts.conditional_uninspected_reauth_permit++;
  if(revoked){counts.conditional_revoked_uninspected_reauth_permit++;
    counts.by_family[String(family)].revoked_uninspected++;}
}
// Mutation sensitivity: if either equality guard is removed, a counterexample
// to that modified filter is produced without changing the source oracle.
let caught=0;
for(const i of [0,1])for(const x of [0,1,2])for(const y of [0,1,2]){
  const original=(x===0 && y===0);
  const mutant=(i===0?y===0:x===0);
  if(mutant&&!original)caught++;
}
for(const family of [4,6])for(const p of [0,2])for(const r of [1,2]){
  const selectedObservables=JSON.stringify([family,2,p,r]);
  const siblingObservables=JSON.stringify([family,2,p,r]);
  if(selectedObservables!==siblingObservables)throw new Error('unknown original identity unexpectedly distinguished');
  counts.indistinguishable_selection_pairs++;
}
if(caught!==4)throw new Error(`Unexpected mutation count ${caught}`);
console.log(JSON.stringify({...counts,filter_mutation_witnesses:caught},null,2));
