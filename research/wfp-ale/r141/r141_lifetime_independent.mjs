// Independent index-based model; never imports Python or Rust.
import {createHash} from 'node:crypto';
const types=['dynamic','static','persistent','boot_time'];
const events=['boot_before_bfe','bfe_active','owner_exited','bfe_runtime_down','bfe_restarted','reboot_before_bfe'];
let hash=createHash('sha256'),counts={},rows=0;
for(let n=0;n<192;n++) {
  const kind=types[Math.floor(n/48)];
  const ev=events[Math.floor(n/8)%6];
  const enabled=Number((n&4)!==0),registered=Number((n&2)!==0),permit=Number((n&1)!==0);
  let state='missing';
  if(kind==='boot_time'){
    if(ev==='boot_before_bfe'||ev==='reboot_before_bfe')state='configured_boot';
  } else if(kind==='persistent') {
    if(['boot_before_bfe','reboot_before_bfe','bfe_runtime_down'].includes(ev))state='stored_only';
    else state='configured';
  } else if(kind==='static') {
    if(ev==='bfe_active'||ev==='owner_exited')state='configured';
  } else if(kind==='dynamic') {
    if(ev==='bfe_active')state='configured';
  }
  if((state==='configured'||state==='configured_boot')&&!enabled)state='provider_disabled_or_unverified';
  if((state==='configured'||state==='configured_boot')&&!registered)
    state=permit?'callout_unregistered_permit_fallback':'callout_unregistered_block_fallback';
  counts[state]=(counts[state]??0)+1;
  hash.update(`${kind}|${ev}|${enabled}|${registered}|${permit}|${state}|0\n`,'ascii');
  rows++;
}
console.log(JSON.stringify({scenarios:rows,all_effective_proof_false:true,statuses:counts,sha256:hash.digest('hex')}));
