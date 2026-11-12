#!/usr/bin/env node
// Independent JS truth table: no host access, no WFP registration, no sockets.
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

const identities = ['selected', 'unrelated', 'missing'];
const currents = ['selected', 'broker', 'third_party', 'missing'];
const endpoints = ['loopback', 'external', 'unknown'];
const rows = [];
function decision(a, b, d, f, proto) {
  // Model construction differs deliberately from the Python enumeration.
  const isTcp = proto === 'tcp';
  const old = Number(isTcp && a === 'selected');
  const c = Number(isTcp && b === 'selected');
  const l = Number(isTcp && a === 'selected' && d === 'loopback');
  return {
    current: b, current_rule: c, dest: d, family: f, legacy: old,
    local_rule: l, original: a, overlap: Number(c===1 && l===1), protocol: proto, split: Math.max(c, l)
  };
}
for (const a of identities) {
  for (const b of currents) {
    for (const d of endpoints) {
      for (const f of [4, 6]) {
        for (const proto of ['tcp', 'udp']) {
          rows.push(decision(a,b,d,f,proto));
        }
      }
    }
  }
}
function find(a,b,d,f,p='tcp') {
  return rows.find(x => x.original === a && x.current === b && x.dest === d && x.family === f && x.protocol === p);
}
for (const f of [4, 6]) {
  assert.deepEqual([find('selected','selected','external',f).legacy, find('selected','selected','external',f).split], [1,1]);
  assert.deepEqual([find('selected','broker','external',f).legacy, find('selected','broker','external',f).split], [1,0]);
  assert.deepEqual([find('selected','broker','loopback',f).legacy, find('selected','broker','loopback',f).split], [1,1]);
  assert.equal(find('selected','selected','loopback',f).overlap,1);
  assert.deepEqual([find('selected','third_party','external',f).legacy, find('selected','third_party','external',f).split], [1,0]);
  assert.deepEqual([find('missing','broker','loopback',f).legacy, find('missing','broker','loopback',f).split], [0,0]);
}
assert.equal(rows.length, 144);
assert(rows.filter(x=>x.protocol==='udp').every(x=>x.legacy===0&&x.split===0));
assert(rows.some(x=>x.legacy===0&&x.split===1));
const canonical = rows.map(x => JSON.stringify(Object.fromEntries(Object.entries(x).sort(([a],[b]) => a.localeCompare(b))))+'\n').join('');
const counts = {};
for (const field of ['legacy','split','current_rule','local_rule','overlap']) counts[field] = rows.reduce((n,r)=>n+r[field],0);
counts.legacy_only = rows.filter(r=>r.legacy&&!r.split).length;
counts.split_only = rows.filter(r=>r.split&&!r.legacy).length;
console.log(JSON.stringify({ cases:rows.length, sha256:createHash('sha256').update(canonical).digest('hex'), counts, checks: 13, pass:true }));
