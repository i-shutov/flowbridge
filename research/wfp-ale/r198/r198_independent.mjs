#!/usr/bin/env node
// Independent source-pattern and input/output oracle. No WFP/socket operations.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const modelOnly=process.argv.slice(2).join(' ')==='--model-only';
if(!modelOnly){
 const p=fs.readFileSync(path.join(root,'kernel-r19/policy_windows.rs'),'utf8').split('fn conditions(')[1].split('fn filter(')[0];
 const a=fs.readFileSync(path.join(root,'kernel-r19/kernel/src/redirect.rs'),'utf8').split('pub unsafe fn auth_classify(')[1];
 const b=fs.readFileSync(path.join(root,'kernel-r19/broker_windows.rs'),'utf8').split('pub fn claim_and_connect_trusted_ssh(')[1].split('impl TrustedSshRelay')[0];
 const guards=[
  p.includes('Kind::AttestOriginal{FWPM_CONDITION_ALE_ORIGINAL_APP_ID}'),
  p.includes('tcp.conditionValue.Anonymous.uint8=6'),
  b.indexOf('SET_RECORDS')>=0 && b.indexOf('SET_RECORDS')<b.indexOf('connect(s.0'),
  b.includes('ip:remote.ip().octets()'),
  a.includes('if !loopback{return false;}'),
  a.includes('if !auth_check(values,meta){block(out);return;}'),
  a.includes('lookup(m.processId)'),
 ];
 if(guards.some(x=>!x))throw Error('Source mismatch: '+JSON.stringify(guards));
 console.log('SOURCE 7/7 (structural only)');
}
const sel='selected.exe',bro='broker.exe';
function decide(o){return o.original!==sel?'UNCLASSIFIED':
 (o.local && o.meta && o.pid===sel && o.ticket?'MODEL_PERMIT':'BLOCK');}
const cases=[
 ['selected_sibling_direct',sel,false,false,sel,false,'BLOCK'],
 ['original_selected_loopback_candidate',sel,true,true,sel,true,'MODEL_PERMIT'],
 ['tagged_ssh_broker_pid',sel,false,true,bro,false,'BLOCK'],
 ['tagged_ssh_even_with_selected_pid',sel,false,true,sel,true,'BLOCK'],
 ['broker_without_selected_original',bro,false,false,bro,false,'UNCLASSIFIED'],
 ['ipv6_selected_original_tagged_ipv4_ssh',sel,false,true,bro,false,'BLOCK'],
];
for(const [n,original,local,meta,pid,ticket,want] of cases){
 const got=decide({original,local,meta,pid,ticket});
 if(got!==want)throw Error(n+': '+got+' != '+want);
 console.log(n,got);
}
console.log('MODEL 6/6; conditional, NOT native WFP proof; model_only=',modelOnly);
