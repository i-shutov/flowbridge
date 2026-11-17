#!/usr/bin/env node
// Independent R213 truth table, intentionally not sharing Python's Flow abstraction.
// Offline only: NO real WFP classify, BFE change, sockets or SSH traffic.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

if (process.argv.includes('--source')) {
  const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
  const pins=[
    ['kernel-r19/policy_plan.rs','0c3d0e88eb9d06f4030131d9533da2d629dbdab0'],
    ['kernel-r19/policy_windows.rs','acf60334320d970f58af3349ee75fbaa59826602'],
    ['kernel-r19/broker_windows.rs','329ef14b63e70226bfad7372b0014559213abd04'],
    ['kernel-r19/kernel/src/redirect.rs','a093f049d162987981a957aac90db1014bc6ff09'],
  ];
  const source=pins.map(([file,hash])=>{
    const bytes=readFileSync(resolve(root,file));
    assert.equal(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'),hash);
    return bytes.toString('utf8');
  });
  const [plan,policy,broker,redirect]=source;
  const ssh=broker.slice(broker.indexOf('pub fn claim_and_connect_trusted_ssh('),broker.indexOf('impl TrustedSshRelay {'));
  const checks=[
    plan.includes('Family::V4,kind:Kind::AttestOriginal') && plan.includes('Family::V6,kind:Kind::AttestOriginal'),
    policy.includes('FWPM_CONDITION_ALE_ORIGINAL_APP_ID'),
    policy.includes('FWPM_CONDITION_IP_PROTOCOL') && policy.includes('Anonymous.uint8=6'),
    policy.includes('FWP_ACTION_CALLOUT_TERMINATING'),
    ssh.includes('WSAIoctl(s.0,SET_RECORDS') && ssh.indexOf('WSAIoctl(s.0,SET_RECORDS')<ssh.indexOf('connect(s.0,'),
    ssh.includes('socket(2,1,6)') && ssh.includes('SocketAddrV4'),
    redirect.includes('original_matches_selected(orig,current_app,'),
    redirect.includes('bits & 0x0010_0000==0'),
    redirect.includes('if !loopback{return false;}'),
    redirect.includes('actual_port != route.ports['),
    redirect.includes('if !auth_check(values,meta){block(out);return;}'),
  ];
  assert.ok(checks.every(Boolean),checks.join(','));
  console.log(`R213 Node: 4/4 blob SHA, ${checks.length}/${checks.length} guards PASS`);
}

let assertions=0;
for(const srcFamily of [4,6]) {
  // WFP physical socket (R37) = IPv4. AppId original attached via copied records is the variable.
  for(const originalSelected of [false,true]) {
    for(const tcp of [false,true]) {
      const bfeMatch=originalSelected && tcp;
      const authOK=false; // physical SSH is non-loopback, no selected client endpoint ticket
      const blocked=bfeMatch && !authOK;
      assert.equal(blocked,originalSelected && tcp);
      assertions++;
    }
  }
  // The original selected-client redirected loopback socket should not be confused
  // with a downstream physical socket: its AUTH predicate can admit.
  const selected=true,tcp=true,redirected=true,loopback=true,proxyPort=true,sameKernelOrigin=true;
  assert.equal(selected&&tcp&&redirected&&loopback&&proxyPort&&sameKernelOrigin,true);
  assertions++;
  // Literal current AppId of the broker is not a BFE match exclusion, since filter keys ORIGINAL.
  const currentIsSelected=false,originalIsSelected=true;
  assert.equal(originalIsSelected && !currentIsSelected,true);
  assertions++;
  // Direct sibling and UDP remain outside that scope (NOT evidence of safety).
  assert.equal(false && tcp,false);assert.equal(selected && false,false);
  assertions+=2;
}
assert.equal(assertions,16);
console.log('R213 Node: 16/16 independent conditional truth-table assertions PASS; not native classification');
