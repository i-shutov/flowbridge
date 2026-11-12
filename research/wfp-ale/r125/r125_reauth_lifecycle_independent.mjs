#!/usr/bin/env node
// R125 independent oracle. Synthetic data only: not a WFP classification or network test.
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
const phases = ['issued', 'authed', 'claimed', 'retired'];
function one(phase, family, protocol, mask) {
  const flag = bit => (mask & (1 << bit)) !== 0;
  // Model permissions as transitions, independently from Python's conjunction.
  if (![4,6].includes(family) || protocol !== 6) return [0,0,0];
  if (!flag(1) || flag(2)) return [0,0,0];
  for (const bit of [3,4,5,6,7]) if (!flag(bit)) return [0,0,0];
  let ticket = {live:true,authSeen:false};
  if (phase === 'authed') ticket.authSeen=true;
  if (phase === 'claimed' || phase === 'retired') {ticket.live=false;ticket.authSeen=true;}
  const afterFlagRemoval = ticket.live && !ticket.authSeen;
  const afterAuthReset = ticket.live;
  const actual = afterFlagRemoval && !flag(0);
  return [Number(actual),Number(afterFlagRemoval),Number(afterAuthReset)];
}
const lines=[];
for (const phase of phases) {
  for (const family of [4,6]) {
    for (const protocol of [6,17]) {
      for (let mask=0;mask<256;mask++) {
        lines.push([phase,family,protocol,mask,...one(phase,family,protocol,mask)].join('|'));
      }
    }
  }
}
assert.equal(lines.length,4096);
assert.deepEqual(one('authed',4,6,251),[0,0,1]);
assert.deepEqual(one('claimed',6,6,251),[0,0,0]);
assert.deepEqual(one('issued',4,6,250),[1,1,1]);
const sum = k => lines.reduce((s,line)=>s+Number(line.split('|')[k]),0);
const result = { cases:lines.length,
  native_admitted:sum(4), without_flag_admitted:sum(5), without_flag_and_auth_reset_admitted:sum(6),
  sha256:createHash('sha256').update(lines.join('\n')+'\n').digest('hex')};
assert.deepEqual([result.native_admitted,result.without_flag_admitted,result.without_flag_and_auth_reset_admitted],[2,4,8]);
console.log(JSON.stringify(result));
