#!/usr/bin/env node
// R207 independently implemented reducer; no Windows, driver or network access.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

if (process.argv.includes('--source')) {
  const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
  const spec=[
    ['redirect','kernel-r19/kernel/src/redirect.rs','a093f049d162987981a957aac90db1014bc6ff09'],
    ['handoff','kernel-r19/kernel/src/handoff.rs','e1d17217db50362ba9c4efc83af820b6beb094cf'],
    ['ledger','r201/selective_ledger.rs','bc4c02daf2f09609cfa11b595d842e5ad2608625'],
  ];
  const code={};
  for(const [name,path,expected] of spec) {
    const bytes=readFileSync(resolve(root,path));
    const digest=createHash('sha1').update(Buffer.from('blob '+bytes.length+'\0')).update(bytes).digest('hex');
    assert.equal(digest,expected,name+' Git blob');
    code[name]=bytes.toString('utf8');
  }
  const a=code.redirect,b=code.handoff,c=code.ledger;
  assert.ok(a.includes('bits & (0x0000_0004|0x0200_0000)!=0{return false;}'));
  assert.ok(a.includes('if !auth_check(values,meta){block(out);return;}'));
  assert.ok(a.includes('route.book.attest(identity,original_destination,now())'));
  assert.ok(!a.split('pub unsafe fn auth_classify(')[1].includes('book.retire('));
  assert.ok(b.includes('slot.auth_seen=true;'));
  assert.ok(b.includes('if !s.auth_seen || s.context!=context'));
  assert.ok(!b.split('pub fn take(')[1].split('pub fn kill(')[0].includes('reauthorize'));
  assert.ok(c.includes('if !redirected || reauthorize || original_appid != self.pins.selected {return Decision::Denied;}'));
  console.log('Independent Node pinned Rust source gates 8/8 PASS (static)');
}
const seed=()=>({entries:new Map(),failed:new Set(),lost:false});
const issue=(fam=4,ep=7,epoch=1)=>({kind:'issue',fam,ep,epoch});
const auth=(fam=4,ep=7,extra={})=>({kind:'auth',fam,ep,epoch:1,reauth:false,metadata:true,original:true,...extra});
const claim=(ep=7,epoch=1)=>({kind:'claim',ep,epoch});
function apply(state, event, strict) {
  const entries=new Map(state.entries),failed=new Set(state.failed);
  const old=entries.get(event.ep);
  let result='NONE';
  if(event.kind==='issue') {
    assert.equal(old,undefined);
    entries.set(event.ep,{fam:event.fam,epoch:event.epoch,live:true,seen:false});
    result='ISSUED';
  } else if(event.kind==='auth') {
    const ok=old && old.live && !old.seen && !event.reauth &&
      event.metadata && event.original && old.fam===event.fam && old.epoch===event.epoch;
    if(ok) {entries.set(event.ep,{...old,seen:true});result='MODEL_AUTH';}
    else {result='BLOCK';if(strict&&old){entries.set(event.ep,{...old,live:false});failed.add(event.ep);}}
  } else if(event.kind==='claim') {
    result=!state.lost && old?.live && old.seen && old.epoch===event.epoch && !failed.has(event.ep)
      ? 'MODEL_CLAIM':'DENY';
    if(old)entries.set(event.ep,{...old,live:false});
  } else if(event.kind==='loss') {
    return {entries,failed,lost:true,result:'STOP'};
  }
  return {entries,failed,lost:state.lost,result};
}
function run(events,strict){
  let state=seed();const out=[];
  for(const e of events){state=apply(state,e,strict);out.push(state.result);}
  return out;
}
let n=0;
for(const fam of [4,6]) {
  const ev=[issue(fam),auth(fam),auth(fam,7,{reauth:true}),claim()];
  assert.equal(run(ev,false).at(-1),'MODEL_CLAIM');
  assert.equal(run(ev,true).at(-1),'DENY');n++;
}
for(const flags of [{reauth:true},{metadata:false},{original:false},{fam:6}]) {
  const ev=[issue(),auth(4,7,flags),auth(),claim()];
  assert.equal(run(ev,false).at(-1),'MODEL_CLAIM');
  assert.equal(run(ev,true).at(-1),'DENY');n++;
}
for(const flags of [{reauth:true},{metadata:false},{original:false}]) {
  const ev=[issue(),auth(),auth(4,7,flags),claim()];
  assert.equal(run(ev,false).at(-1),'MODEL_CLAIM');
  assert.equal(run(ev,true).at(-1),'DENY');n++;
}
for(const strict of [false,true]) {
  assert.equal(run([issue(),auth(),auth(4,8,{reauth:true}),claim()],strict).at(-1),'MODEL_CLAIM');n++;
}
assert.equal(run([issue(),auth(),claim(7,9),claim()],false).at(-1),'DENY');n++;
assert.equal(run([issue(),auth(),{kind:'loss'},claim()],false).at(-1),'DENY');n++;
console.log('R207 independent Node negative model '+n+'/'+n+' PASS (synthetic; not kernel proof)');
