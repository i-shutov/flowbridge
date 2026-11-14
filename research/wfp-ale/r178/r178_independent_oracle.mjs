// Independent combinatorial oracle. Does NOT import the Python state machine.
// Merge two ordered chains after R, using combinations of 4 slots from 8.
// This describes all 70 possible two-lane schedules (C(8,4)).
import assert from 'node:assert/strict';
const a = 'PACS', b = 'QLJK';
const schedules = [];
for (let mask = 0; mask < 256; mask++) {
  if (mask.toString(2).replaceAll('0','').length !== 4) continue;
  let ia = 0, ib = 0, word = 'R';
  for (let pos = 0; pos < 8; pos++) {
    if ((mask & (1 << pos)) !== 0) word += a[ia++];
    else word += b[ib++];
  }
  schedules.push(word);
}
schedules.sort();
assert.equal(schedules.length, 70);
assert.equal(new Set(schedules).size, 70);
function predicate(s, before, after) { return s.indexOf(before) < s.indexOf(after); }
const result = [];
for (const family of [4, 6]) for (const s of schedules) {
  const before = (x, y) => predicate(s, x, y);
  result.push([family, s, before('S','Q'), before('S','J'), before('S','K'),
    before('C','K'), before('Q','P'), before('K','C'),
    before('Q','P') && before('K','C')]);
}
assert.deepEqual(result.slice(0,70).reduce((counts, r) =>
  counts.map((n, i) => n + Number(r[i+2])), Array(7).fill(0)), [1,15,35,55,35,15,10]);
assert.equal(result.filter(r=>r[2]).map(r=>r[1]).join(','), 'RPACSQLJK,RPACSQLJK');
// Independently check the failure predicates without invoking the Python model.
const forwarding = (ticket, auth, ack, terminal, gated) => ticket && auth && (!gated || (ack && !terminal));
assert.equal(forwarding(true, true, false, true, false), true);   // queue full, weak book
assert.equal(forwarding(true, true, false, true, true), false);   // queue full, gated book
assert.equal(forwarding(true, true, false, false, true), false);  // journal failed
assert.equal(forwarding(true, true, true, true, true), false);    // BFE/SSH revoked
assert.equal(forwarding(true, true, true, false, true), true);    // model-only happy path
for (const r of result) console.log(JSON.stringify(r));
