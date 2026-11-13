// R158: source-pinned target split negative regression. NO native WFP or network.
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
const root=process.argv[2]||process.cwd();
const pins={
 'research/wfp-ale/kernel-r19/policy_windows.rs':'acf60334320d970f58af3349ee75fbaa59826602',
 'research/wfp-ale/kernel-r19/kernel/src/redirect.rs':'a093f049d162987981a957aac90db1014bc6ff09',
 'research/wfp-ale/kernel-r19/kernel/src/lib.rs':'53f5ce6faa0f9f591974287f38ea890cafeb0dd2'
};
const src={};
for(const [name,want] of Object.entries(pins)){
 const bytes=fs.readFileSync(path.join(root,name));
 const hdr=Buffer.from(`blob ${bytes.length}\0`);
 const got=crypto.createHash('sha1').update(hdr).update(bytes).digest('hex');
 if(got!==want)throw Error(`REJECT_SOURCE_CHANGED ${name}: ${got}`);
 src[name]=bytes.toString('utf8');
}
const policy=src['research/wfp-ale/kernel-r19/policy_windows.rs'];
const redirect=src['research/wfp-ale/kernel-r19/kernel/src/redirect.rs'];
for(const token of ['FWPM_CONDITION_ALE_ORIGINAL_APP_ID','FWPM_CONDITION_ALE_APP_ID',
 'tcp.conditionValue.Anonymous.uint8=6','blob.size=p.appid.len() as u32'])
 if(!policy.includes(token))throw Error(`REJECT_FILTER_CONTRACT ${token}`);
for(const token of ['if r.configured||input.len()!=h::ARM_LEN',
 'input[16..16+n]==broker.name[..broker.name_len]',
 'r.name[..n].copy_from_slice(&input[16..16+n])',
 'if appid!=&r.name[..r.len]{return;}'])
 if(!redirect.includes(token))throw Error(`REJECT_ARM_CONTRACT ${token}`);
const rows=[];
for(const family of ['V4','V6'])for(const protocol of ['TCP','UDP'])
for(const policy_exe of ['A','B'])for(const arm_exe of ['A','B','C'])
for(const origin_exe of ['A','B','C'])for(const policy_active of [false,true]){
 const arm_accepted_model=arm_exe!=='C'; // broker is distinct process C, with live ledger record
 const hit=policy_active&&protocol==='TCP'&&origin_exe===policy_exe;
 rows.push({family,protocol,policy_exe,arm_exe,origin_exe,policy_active,
  arm_accepted_model,redirect_filter_match:hit,auth_filter_match:hit,
  selected_but_unmatched:arm_accepted_model&&arm_exe===origin_exe&&
    policy_active&&protocol==='TCP'&&!hit});
}
const sort=o=>Object.fromEntries(Object.entries(o).sort(([a],[b])=>a<b?-1:a>b?1:0));
const hash=crypto.createHash('sha256').update(rows.map(r=>JSON.stringify(sort(r))).join('\n')+'\n').digest('hex');
const witnesses=rows.filter(r=>r.selected_but_unmatched);
if(rows.length!==144||witnesses.length!==4||hash!=='41c6f7e594823657eaab70da86075a12f6aec4928d63b26e0c3bc668514a7d45')
 throw Error('MODEL_OR_PINNED_MATRIX_MISMATCH');
for(const r of witnesses)if(r.arm_exe===r.policy_exe||r.origin_exe!==r.arm_exe)
 throw Error('INVALID_COUNTEREXAMPLE');
console.log(JSON.stringify({claim:'FILTER_MATCH_ONLY_NOT_PACKET_PROOF',rows:rows.length,
 counterexamples:witnesses.length,sha256:hash,witnesses}));
