// Independently defined R219 abstract truth table and R218 mismatch detector.
// Node-only; no Windows APIs, network, WFP, processes or drivers.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
const here = new URL('.', import.meta.url);
const r219 = fs.readFileSync(new URL('r219_current_app_model.rs', here),'utf8');
const r218 = fs.readFileSync(new URL('../r218/r218_proxy_auth_model.rs', here),'utf8');
const kernel = fs.readFileSync(new URL('../kernel-r19/kernel/src/auth_appid.rs',here),'utf8');
assert.match(kernel, /valid_utf16_units\(current\)/);
assert.match(kernel, /original\s*==\s*selected/);
assert.match(r218, /f\.current\s*!=\s*App::Other/);
assert.match(r219, /f\.current\s*!=\s*App::Malformed/);
assert.doesNotMatch(r219, /f\.current\s*!=\s*App::ValidThird/);
assert.match(r219, /#!\[forbid\(unsafe_code\)\]/);
const cases = [
  // label, original, current, proto, peer, redirected, reauth, pid, ticket, expected
  ['original','selected','selected','tcp','loopback',1,0,1,1,'PERMIT'],
  ['broker-current','selected','broker','tcp','loopback',1,0,1,1,'PERMIT'],
  ['third-current','selected','third','tcp','loopback',1,0,1,1,'PERMIT'],
  ['malformed-current','selected','malformed','tcp','loopback',1,0,1,1,'BLOCK'],
  ['third-no-ticket','selected','third','tcp','loopback',1,0,1,0,'BLOCK'],
  ['third-reauth','selected','third','tcp','loopback',1,1,1,1,'BLOCK'],
  ['third-other-peer','selected','third','tcp','other',1,0,1,1,'BLOCK'],
  ['third-no-redir','selected','third','tcp','loopback',0,0,1,1,'BLOCK'],
  ['tagged-ssh-v4','selected','broker','tcp','ssh',1,0,1,0,'BLOCK'],
  ['tagged-ssh-v6','selected','broker','tcp','ssh',1,0,1,1,'BLOCK'],
  ['selected-direct','selected','selected','tcp','other',0,0,0,0,'BLOCK'],
  ['selected-udp','selected','selected','udp','other',0,0,0,0,'NOT_SCOPED'],
  ['broker-original','broker','selected','tcp','loopback',1,0,1,1,'NOT_SCOPED'],
  ['third-original','third','broker','tcp','loopback',1,0,1,1,'NOT_SCOPED'],
  ['malformed-original','malformed','broker','tcp','ssh',1,0,1,1,'NOT_SCOPED'],
  ['missing-pid','selected','broker','tcp','loopback',1,0,0,1,'BLOCK']
];
function oracle(row,{useCurrentForScope=false, rejectThird=false, skipLoopback=false, acceptMalformed=false}={}) {
  const [,original,current,proto,peer,redirected,reauth,pid,ticket] = row;
  if ((useCurrentForScope?current:original)!=='selected' || proto!=='tcp') return 'NOT_SCOPED';
  if ((!acceptMalformed && current==='malformed') || (rejectThird && current==='third')) return 'BLOCK';
  return redirected && !reauth && (skipLoopback || peer==='loopback') && pid && ticket ? 'PERMIT':'BLOCK';
}
for(const row of cases) assert.equal(oracle(row),row[9],row[0]);
const oldModelDisagreements = cases.filter(row => oracle(row,{rejectThird:true})!==row[9]).map(row=>row[0]);
assert.deepEqual(oldModelDisagreements,['third-current']);
const mutants = [
  {useCurrentForScope:true}, {skipLoopback:true}, {acceptMalformed:true}
].map(m=>cases.filter(row=>oracle(row,m)!==row[9]).length);
assert.ok(mutants.every(n=>n>0));
const digest = crypto.createHash('sha256').update(cases.map(r=>r.join('|')).join('\n')).digest('hex');
console.log('R219 '+cases.length+'/'+cases.length+' PASS; R218 counterexample '+oldModelDisagreements.join(',')+'; mutation disagreements '+mutants.join('/')+'; sha256 '+digest);
