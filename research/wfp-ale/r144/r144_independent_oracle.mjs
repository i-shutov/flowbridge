// R144: independent JS oracle. No network/WFP/kernel or system mutations.
import assert from "node:assert/strict";
const boot = {object_kind:"SEPARATE_BOOT_DESIGN",persistent_flag_combined:false,runtime_bfe_restart_coverage:"UNPROVEN"};
const state = {initial:"BLOCKING_BASELINE",states:["BLOCKING_BASELINE","VERIFIED_REDIRECT_READY","REVOKING","RECOVERY"],events:["ASSEMBLE","WITNESS_READY","REVOKE_COMPLETE"],ready_requires:["selected_image_pinned"],ready_observations_proven:false,state_names_are_model_only:true};
const vectors = [
 ["boot_false_to_zero",boot,"persistent_flag_combined",0],
 ["ready_proven_false_to_zero",state,"ready_observations_proven",0],
 ["model_only_true_to_one",state,"state_names_are_model_only",1],
 ["boot_false_to_one",boot,"persistent_flag_combined",1],
 ["ready_proven_false_to_one",state,"ready_observations_proven",1],
 ["model_only_true_to_zero",state,"state_names_are_model_only",0],
 ["boot_false_to_string",boot,"persistent_flag_combined","false"],
 ["model_only_true_to_null",state,"state_names_are_model_only",null],
];
function pythonEq(a,b) {
 if (typeof a==="boolean" && typeof b==="number") return Number(a)===b;
 if (typeof b==="boolean" && typeof a==="number") return a===Number(b);
 return JSON.stringify(a)===JSON.stringify(b);
}
function dictEqual(a,b,typed=false){
 return Object.keys(a).length===Object.keys(b).length &&
 Object.keys(a).every(k=>Object.hasOwn(b,k) && (!typed || typeof a[k]===typeof b[k]) && pythonEq(a[k],b[k]));
}
let legacyFalseAccept=0;
for(const [label,ref,field,replacement] of vectors) {
 const forged={...ref,[field]:replacement};
 const old=dictEqual(ref,forged), strict=dictEqual(ref,forged,true);
 assert.equal(strict,false,label);
 legacyFalseAccept+=Number(old);
 console.log(`${label}|old=${Number(old)}|strict=${Number(strict)}`);
}
assert.equal(legacyFalseAccept,3);
console.log("negative_regressions=8; old_false_accept=3; strict_false_accept=0; native_wfp_executed=false");
