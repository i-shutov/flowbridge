#!/usr/bin/env node
// Independent event-position oracle. No Windows, sockets, network, driver or WFP.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
if(process.argv.includes('--source')){
 const pins=[['kernel-r19/kernel/src/redirect.rs','a093f049d162987981a957aac90db1014bc6ff09'],
             ['kernel-r19/kernel/src/lib.rs','53f5ce6faa0f9f591974287f38ea890cafeb0dd2']];
 const [r,lib]=pins.map(([p,expected])=>{
  const b=fs.readFileSync(path.join(root,p));
  const sha=crypto.createHash('sha1').update('blob '+b.length+'\0').update(b).digest('hex');
  assert.equal(sha,expected);return b.toString('utf8');
 });
 const a=r.indexOf('let issue={let _lock=Guard::take();');
 const b=r.indexOf('let Some((context,broker,port))=issue else{block(out);return;};',a);
 const c=r.indexOf('(*out).rights|=incoming_write;(*out).actionType=k::FWP_ACTION_PERMIT;',b);
 const between=r.slice(b,c);
 const checks=[a>=0&&a<b&&b<c,!between.includes('ready('),between.includes('request.localRedirectContext=memory'),
  between.includes('if memory.is_null(){let _lock=Guard::take();'),
  r.includes('if code==h::STOP{lose();return super::SUCCESS;}'),
  r.includes('r.armed=false;r.book.kill();'),
  lib.includes('(*STATE.0.get()).died(id,process as usize);redirect::process_exit(id);'),
  r.indexOf('drop(w);',c)>c];
 assert.ok(checks.every(Boolean),checks.join(','));
 console.log('2 exact Git blob pins; 8/8 source-order guards PASS');
}
const perms=(a,b,c)=>[[a,b,c],[a,c,b],[b,a,c],[b,c,a],[c,a,b],[c,b,a]];
let eligible=0,late=0,controls=0;
for(const loss of ['STOP','OWNER_EXIT']){
 let observed=0;
 for(const seq of perms('ISSUE',loss,'APPLY')){
  if(seq.indexOf('ISSUE')>=seq.indexOf('APPLY')) continue;
  eligible++;
  const issued=seq.indexOf('ISSUE')<seq.indexOf(loss);
  const applied=issued;
  const bad=applied && seq.indexOf(loss)<seq.indexOf('APPLY');
  const fenced=issued && seq.indexOf('APPLY')<seq.indexOf(loss);
  assert.ok(!(bad&&fenced));
  observed+=Number(bad);late+=Number(bad);controls++;
 }
 assert.equal(observed,1);
}
assert.equal(eligible,6);assert.equal(late,2);assert.equal(controls,6);
console.log('R212 Node: 6 ordered schedules, 2 post-invalidation APPLY negatives, 6 fenced controls; NOT native WFP');
