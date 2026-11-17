#!/usr/bin/env node
// R211 independent JS truth-table oracle, mutation sensitivity, no network/driver.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
const TTL=100_000_000n, LEASE=30_000_000n;
function temporal(now, born, ping, {withoutTtl=false,withoutLease=false,withoutOrder=false}={}){
  const ordered=withoutOrder || (now>=born && now>=ping);
  const withinTtl=withoutTtl || now-born<=TTL;
  const withinLease=withoutLease || now-ping<=LEASE;
  return ordered && withinTtl && withinLease;
}
// R201 has no timestamp parameter in its claim API; existing AUTH remains true.
function r201(state){return state.auth && state.owner && state.broker && state.health && !state.used;}
let checks=0;
function check(ok,label){assert.ok(ok,label);checks++;}
for(const family of [4,6]){
  const s={family,auth:true,owner:true,broker:true,health:true,used:false};
  check(r201(s),'R201 static baseline');
  check(!temporal(TTL+8n,1n,TTL+8n),'R19 expired context');
  check(temporal(TTL+8n,1n,TTL+8n,{withoutTtl:true}),'detect TTL mutation');
  check(!temporal(LEASE+9n,1n,1n),'R19 expired lease');
  check(temporal(LEASE+9n,1n,1n,{withoutLease:true}),'detect lease mutation');
  check(!temporal(9n,10n,10n),'R19 clock reversal');
  check(temporal(9n,10n,10n,{withoutOrder:true}),'detect clock-order mutation');
  check(temporal(TTL+1n,1n,TTL+1n),'R19 exact TTL boundary');
  s.used=true;check(!r201(s),'terminal claim');
  s.used=false;s.health=false;check(!r201(s),'explicit health loss');
}
function sourceGate(){
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const pins=[
    ['r201/selective_ledger.rs','bc4c02daf2f09609cfa11b595d842e5ad2608625'],
    ['kernel-r19/kernel/src/handoff.rs','e1d17217db50362ba9c4efc83af820b6beb094cf'],
    ['kernel-r19/kernel/src/redirect.rs','a093f049d162987981a957aac90db1014bc6ff09']
  ];
  const [r201,book,redirect]=pins.map(([p,expected])=>{
    const bytes=fs.readFileSync(path.join(root,p));
    const observed=crypto.createHash('sha1').update('blob '+bytes.length+'\0').update(bytes).digest('hex');
    assert.equal(observed,expected,p);
    return bytes.toString('utf8');
  });
  const guards=[
    /pub fn claim\(&mut self, id: &Identity, endpoint: u64\) -> Decision/.test(r201),
    !/pub fn claim\(&mut self, id: &Identity, endpoint: u64,\s*now:/.test(r201),
    /pub const TTL: u64 = 100_000_000/.test(book),
    /pub const LEASE: u64 = 30_000_000/.test(book),
    /pub fn take\(&mut self, context:Context, now:u64\)/.test(book),
    /now<context.number\(96\) \|\| now-context.number\(96\)>TTL/.test(book),
    /time<r.last\|\|time-r.last>h::LEASE/.test(redirect),
    /book\.take\(c,time\)/.test(redirect),
  ];
  check(guards.every(Boolean),'source structural guards');
  console.log('3 pinned Git blobs and 8/8 JS source guards PASS');
}
if(process.argv.includes('--source'))sourceGate();
console.log('R211 JS independent temporal oracle: '+checks+' checks PASS; NOT native WFP/Rust proof');
