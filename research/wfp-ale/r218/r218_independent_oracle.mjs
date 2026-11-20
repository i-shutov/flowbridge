// Independent R218 source-contract negative oracle; no WFP, sockets or drivers.
// Rust model is not compiled here. This verifies a separately implemented truth
// table and mutation sensitivity, NOT an observed Windows classify event.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
const rust=fs.readFileSync(new URL('./r218_proxy_auth_model.rs',import.meta.url),'utf8');
for(const token of ['#![forbid(unsafe_code)]','fn auth_filter_matches','fn auth_decision',
 'tagged_ssh_is_self_blocked_if_original_app_id_propagates','direct_selected_tcp_blocked_udp_out_of_scope']){
 assert.ok(rust.includes(token),`Rust source-contract marker missing: ${token}`);
}
const rows=[
 ['original-loopback', 'selected','selected','tcp','loopback',1,0,1,1,'PERMIT'],
 ['tagged-ssh-v4','selected','broker','tcp','ssh',1,0,1,0,'BLOCK'],
 ['tagged-ssh-v6','selected','broker','tcp','ssh',1,0,1,0,'BLOCK'],
 ['tagged-ssh-with-ticket','selected','broker','tcp','ssh',1,0,1,1,'BLOCK'],
 ['untagged-broker-ssh','broker','broker','tcp','ssh',0,0,0,0,'OUT_OF_SCOPE'],
 ['selected-direct-tcp','selected','selected','tcp','other',0,0,0,0,'BLOCK'],
 ['selected-direct-udp','selected','selected','udp','other',0,0,0,0,'OUT_OF_SCOPE'],
 ['selected-reauthorize','selected','selected','tcp','loopback',1,1,1,1,'BLOCK'],
 ['selected-no-ticket','selected','selected','tcp','loopback',1,0,1,0,'BLOCK'],
 ['selected-wrong-pid','selected','selected','tcp','loopback',1,0,0,1,'BLOCK'],
 ['broker-original-selected-current','broker','selected','tcp','loopback',1,0,1,1,'OUT_OF_SCOPE'],
 ['other-original-broker-current','other','broker','tcp','ssh',1,0,0,0,'OUT_OF_SCOPE']
];
function evalIndependent([,original,current,protocol,target,redir,reauth,pid,ticket], mutate={}){
 const scope=((mutate.useCurrent?current:original)==='selected' && protocol==='tcp');
 if(!scope)return 'OUT_OF_SCOPE';
 const permit=redir && !reauth && (mutate.skipLoopback || target==='loopback') &&
   pid && ticket && current!=='other';
 return permit?'PERMIT':'BLOCK';
}
for(const r of rows)assert.equal(evalIndependent(r),r.at(-1),r[0]);
const mutations=[{useCurrent:true},{skipLoopback:true}].map(m=>rows.filter(r=>evalIndependent(r,m)!==r.at(-1)).length);
assert.ok(mutations.every(n=>n>0),`weak negative oracle: ${mutations}`);
const sha=crypto.createHash('sha256').update(rows.map(r=>`${r[0]}|${r.at(-1)}`).join('\n')).digest('hex');
console.log(`R218: ${rows.length}/${rows.length} independent matrix PASS; mutation disagreements ${mutations.join('/')}; canonical_sha256 ${sha}`);
