#!/usr/bin/env node
// Independent R70 offline interpreter: explicit Boolean decoding, no imports
// except built-in crypto; never opens network sockets, filters or drivers.
import {createHash} from 'node:crypto';
const present = (word, position) => ((word >>> position) & 1) === 1;
function evaluateAuth(word) {
  const observed = present(word, 13);
  if (!observed) return 0;
  const metadata = [0,1,2,3].every(k => present(word, k));
  if (!metadata) return 1;
  if (!present(word, 4)) return 2;
  const gates = [5,6,7,8,9,10,11,12];
  for (const flag of gates) if (!present(word, flag)) return 3;
  return 4; // CONDITIONAL, NEVER ORIGIN_PROVED
}
function evaluateRedirect(word) {
  const callback = present(word, 7);
  if (!callback) return 0;
  if (!(present(word, 2) && present(word, 3))) return 1;
  if (!(present(word, 4) && present(word, 5))) return 2;
  if (!present(word, 0)) return 3;
  if (!present(word, 1)) return 4;
  return 5;
}
let a = new Uint8Array(65536 * 2), r = new Uint8Array(256 * 2);
let ai = 0, ri = 0;
let hiddenOwner = 0, sibling = 0, unknownForeign = 0;
for (const family of [4, 6]) {
  for (let v = 0; v < 65536; ++v) {
    const result = evaluateAuth(v);
    a[ai++] = result;
    if (result === 4 && !present(v,14)) hiddenOwner++;
    if (result === 4 && present(v,15)) sibling++;
  }
  for (let v = 0; v < 256; ++v) {
    const result = evaluateRedirect(v);
    r[ri++] = result;
    if (result === 3 && present(v,6)) unknownForeign++;
  }
}
function counts(data,n){return Object.fromEntries(Array.from({length:n},(_,i)=>[String(i),data.reduce((total,v)=>total+(v===i),0)]));}
const out={auth_cases:a.length,auth_counts:counts(a,5),auth_sha256:createHash('sha256').update(a).digest('hex'),redirect_cases:r.length,redirect_counts:counts(r,6),redirect_sha256:createHash('sha256').update(r).digest('hex'),conditional_with_hidden_wrong_owner:hiddenOwner,conditional_with_hidden_sibling_direct_possible:sibling,unqueried_with_hidden_foreign_redirect:unknownForeign};
console.log(JSON.stringify(out,null,2));
