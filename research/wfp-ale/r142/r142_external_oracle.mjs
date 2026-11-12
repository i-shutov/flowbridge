// Independent outer runner validates observed Python 3 normal/-O gates.
// Only launches local, source-pinned Python probe. Never invokes WFP, network or driver.
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const test=new URL('./r142_negative_suite.py',import.meta.url).pathname;
const cases=['valid','permit_unregistered','protocol_swap','layer_swap',
             'action_swap','missing_filter','native_proof_claim',
             'boot_fake_proof','provider_activated'];
let sha=createHash('sha256'),count=0;
for(const mode of ['normal','optimized']){
  for(const c of cases){
    const args=['-B',...(mode==='optimized'?['-O']:[]),test,'--probe',c];
    const r=spawnSync(process.env.PYTHON || 'python3',args,{encoding:'utf8',timeout:15000});
    if(r.error || r.status!==0 || r.stderr!=='' || !['ACCEPT','REJECT'].includes(r.stdout.trim()))
      throw Error(`invalid probe ${mode}:${c} ${r.status}:${r.stderr}`);
    const expected=c==='valid'?'ACCEPT':'REJECT';
    if(r.stdout.trim()!==expected)throw Error(`FAIL_OPEN ${mode}:${c}`);
    sha.update(`${mode}|${c}|${r.stdout.trim()}\n`,'ascii');count++;
  }
}
console.log(JSON.stringify({checks:count,failed:0,sha256:sha.digest('hex')}));
