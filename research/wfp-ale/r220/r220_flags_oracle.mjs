// R220 independent negative oracle, no sockets, WFP, driver, or Windows APIs.
// Executing this JS does NOT compile or execute the sibling Rust model.
// Official flag values: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';

const root = new URL('../', import.meta.url);
const r19path = new URL('kernel-r19/kernel/src/redirect.rs', root);
const r19 = fs.existsSync(r19path) ? fs.readFileSync(r19path,'utf8') : null;
const rust = fs.readFileSync(new URL('r220/r220_auth_flags_model.rs', root),'utf8');
if (r19 !== null) {
  for (const token of ['bits & 0x0010_0000==0','0x0000_0004|0x0200_0000','route.book.attest']) {
    assert.ok(r19.includes(token),`R19 source contract changed: ${token}`);
  }
} else console.warn('R19 source unavailable locally: runtime source-contract check skipped; repository checkout must include kernel-r19');
for (const token of ['#![forbid(unsafe_code)]','PROXY_CONNECTION: u32 = 0x0020_0000','CONNECTION_REDIRECTED: u32 = 0x0010_0000','fn r19_auth_candidate']) {
  assert.ok(rust.includes(token),`R220 Rust contract changed: ${token}`);
}
// Independent combinatorial oracle derived from R19 branch conditions; variables
// refer ONLY to synthetic observations, never to actual Windows socket flags.
const seen = {OUT_OF_SCOPE:0,BLOCK:0,CANDIDATE:0};
const vectors = [];
function verdict(x,m={}) {
  if (!x.selected || !x.tcp) return 'OUT_OF_SCOPE';
  const effectiveRedirected = m.conflateProxy ? (x.flags & 0x00300000) !== 0 : (x.flags & 0x00100000) !== 0;
  const noReauth = m.ignoreReauth ? true : (x.flags & 0x00000004) === 0;
  const noHonoring = m.ignoreHonoring ? true : (x.flags & 0x02000000) === 0;
  const metadata = m.ignoreMetadata ? true : x.metadata;
  const loopback = m.ignoreDestination ? true : x.loopback;
  return effectiveRedirected && noReauth && noHonoring && x.validApp && loopback && metadata && x.origin
    ? 'CANDIDATE' : 'BLOCK';
}
// Include exact flag bits as separate dimensions, not a boolean "redirected".
for(let mask=0;mask<16;mask++)for(let v=0;v<128;v++) {
  const x={
    flags:((mask&1)?0x00100000:0)|((mask&2)?0x00200000:0)|((mask&4)?0x00000004:0)|((mask&8)?0x02000000:0),
    selected:!!(v&1),tcp:!!(v&2),validApp:!!(v&4),
    loopback:!!(v&8),metadata:!!(v&16),origin:!!(v&32)
  };
  // bit 64 is an independent irrelevant flag, which must have no effect.
  x.flags |= (v&64) ? 0x00000001 : 0;
  const out=verdict(x);seen[out]++;vectors.push({x,out});
}
assert.equal(vectors.length,2048);
const row=(flags,extra={})=>verdict({flags,selected:true,tcp:true,validApp:true,loopback:true,metadata:true,origin:true,...extra});
assert.equal(row(0x00100000),'CANDIDATE');
assert.equal(row(0x00200000),'BLOCK');   // PROXY_CONNECTION alone is not REDIRECTED
assert.equal(row(0x00300000),'CANDIDATE'); // both flags: ticket still required
assert.equal(row(0x00300000,{loopback:false}),'BLOCK');
assert.equal(row(0x00100004),'BLOCK');
assert.equal(row(0x02100000),'BLOCK');
assert.equal(row(0x00200000,{selected:false}),'OUT_OF_SCOPE');
const mutations=[{conflateProxy:true},{ignoreReauth:true},{ignoreHonoring:true},
 {ignoreMetadata:true},{ignoreDestination:true}].map(m=>vectors.reduce((n,{x,out})=>n+(verdict(x,m)!==out),0));
assert.ok(mutations.every(n=>n>0),`mutation survived: ${mutations}`);
const digest=crypto.createHash('sha256').update(vectors.map(({x,out})=>[x.flags,x.selected,x.tcp,x.validApp,x.loopback,x.metadata,x.origin,out].join('|')).join('\n')).digest('hex');
console.log(`R220: ${vectors.length}/${vectors.length} synthetic flag vectors; ${JSON.stringify(seen)}; mutations ${mutations.join('/')}; sha256 ${digest}`);
