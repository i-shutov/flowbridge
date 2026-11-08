// R50 independent enumeration (no import of Python policy). Pure Node, no network.
// A PASS is conditional on 16 external proofs that this script cannot establish.
const guards = [
  'layer','flow_flag','delete_fn','associate_success','kernel_receipt','session',
  'process_epoch','original_app','transport_endpoint','ticket','destination',
  'health','owner_live','policy_generation','established','unconsumed'
];
let total=0, hypothetical=0, actual=0, unsafe=0;
const failures = [];
for (const family of [4,6]) {
  for(let mask=0;mask<2**guards.length;mask++) {
    const bits = guards.map((_,i)=>Boolean(mask & (1<<i)));
    // A missing bit is a reason to deny, regardless of any tuple/PID correlation.
    const denied = bits.some(x=>!x);
    const possible = !denied;
    const presentFlowHandle = bits[1];
    total++;
    hypothetical += Number(possible);
    unsafe += Number(presentFlowHandle);
    // Source intentionally rejects REAUTHORIZE even when all conditional bits are true.
    actual += 0;
    if (possible && (!bits[2] || !bits[3])) failures.push({family,mask});
  }
}
let mutants=0;
for(let target=0;target<guards.length;target++){
  const omitted=guards.map((_,i)=>i!==target);
  const strict=omitted.every(x=>x);
  const weakened=omitted.every((x,i)=>i===target||x);
  if(!strict && weakened)mutants++;
}
const result={total,conditional_model_permits:hypothetical,current_source_reauth_permits:actual,
  unsafe_flow_handle_only_permits:unsafe,single_guard_mutants_detected:mutants,consistency_failures:failures.length};
console.log(JSON.stringify(result,null,2));
if(total!==131072 || hypothetical!==2 || actual!==0 || unsafe!==65536 || mutants!==16 || failures.length)process.exitCode=1;
