// R202 source-bound negative checks. Complete checkout required to run locally.
// These predicates are NOT WFP runtime, packet, kernel or OS provenance tests.
import {readFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..','kernel-r19');
const policy=readFileSync(resolve(root,'policy_windows.rs'),'utf8');
const plan=readFileSync(resolve(root,'policy_plan.rs'),'utf8');
const kernel=readFileSync(resolve(root,'kernel/src/lib.rs'),'utf8');
const redirect=readFileSync(resolve(root,'kernel/src/redirect.rs'),'utf8');
const assertions=[
 ['dynamic policy session', /session\.flags\s*=\s*FWPM_SESSION_FLAG_DYNAMIC/,policy],
 ['session closes on explicit close / Drop', /FwpmEngineClose0\(/,policy],
 ['installed policy owns engine handle', /pub struct Installed\s*\{\s*engine\s*:\s*Engine\s*\}/,policy],
 ['installation bound to dynamic engine', /policy_plan::install\(&mut engine,plan\)/,policy],
 ['filter insertion uses session handle', /FwpmFilterAdd0\(self\.handle/,policy],
 ['filter not persistent', /f\.flags\s*=\s*0\s*;/,policy],
 ['TCP-only filtering', /tcp\.conditionValue\.Anonymous\.uint8\s*=\s*6/,policy],
 ['original-app filter branch', /FWPM_CONDITION_ALE_ORIGINAL_APP_ID/,policy],
 ['all scoped rules installed', /for rule in RULES\s*\{\s*api\.filter\(rule,plan\)\?;\s*\}/,plan],
 ['four scoped rules', /RULES\s*:\s*\[Rule;\s*4\]/,plan],
 ['kernel callout registration separate from policy', /FwpsCalloutRegister1\(/,kernel],
 ['kernel auth callback only when called', /pub unsafe fn auth_classify\(/,redirect],
];
for(const [name,regex,input] of assertions){assert.match(input,regex,name);}
assert.doesNotMatch(policy,/FWPM_FILTER_FLAG_PERSISTENT|FWPM_SESSION_FLAG_RESERVED/,'no persistent policy');
assert.doesNotMatch(policy,/FwpmFilterAdd0\(\s*ptr::null_mut\(/,'filter uses engine handle');
const mutated=policy.replace('session.flags=FWPM_SESSION_FLAG_DYNAMIC','session.flags=0');
assert.doesNotMatch(mutated,assertions[0][1],'mutation of session lifetime detected');
console.log('R202 '+assertions.length+'/12 source predicates PASS; persistent-policy check PASS; mutation PASS; no WFP runtime');
