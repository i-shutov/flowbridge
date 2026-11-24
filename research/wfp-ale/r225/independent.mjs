// Independent decision-table oracle. No native API, no pointer dereference.
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
const rows = [];
for (const [layer, required, width] of [[4,2,16],[6,23,28]]) {
  for (const af of [2,23,99]) for (const n of [1,2,16,28,128]) {
    const enough = n >= width, same = af === required;
    const legacy = enough ? (same ? 'MATCH' : 'REJECT') : 'EXTENT';
    const staged = n < 2 ? 'EXTENT' : !same ? 'REJECT' : enough ? 'MATCH' : 'EXTENT';
    rows.push([layer,af,n,legacy,staged].join(',')+'\n');
  }
}
assert.equal(rows.length,30);
assert.equal(rows.filter(r=>r.endsWith('EXTENT,REJECT\n')).length,6);
assert(rows.includes('6,2,16,EXTENT,REJECT\n'));
assert(rows.includes('6,23,28,MATCH,MATCH\n'));
assert(rows.includes('4,23,28,REJECT,REJECT\n'));
console.log(rows.length,createHash('sha256').update(rows.join('')).digest('hex'));
