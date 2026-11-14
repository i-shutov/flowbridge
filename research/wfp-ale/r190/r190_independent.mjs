// Independent table-based model. No Windows, driver or socket operations.
import { createHash } from 'node:crypto';
const family = ['v4', 'v6'];
const kind = ['AUTH', 'REDIRECT'];
const weight = ['EMPTY', 'UINT64', 'UINT8'];
const foreign = ['NONE', 'HIGHER_SAME', 'LOWER_SAME', 'HIGHER_OTHER_LAYER', 'HIDDEN_HIGHER'];
const verdict = {
  NONE: { visible: false, shadows: false },
  HIGHER_SAME: { visible: true, shadows: true },
  LOWER_SAME: { visible: true, shadows: false },
  HIGHER_OTHER_LAYER: { visible: false, shadows: false },
  HIDDEN_HIGHER: { visible: false, shadows: true },
};
const lines = [];
let oldYes = 0, newYes = 0, shadowedOld = 0, shadowedNew = 0;
for (const f of family) for (const k of kind) for (const w of weight)
 for (const o of foreign) for (const a of [0,1]) for (const b of [0,1]) for (const r of [0,1]) {
    const healthy = Boolean(a && b && r);
    const before = healthy ? 1 : 0;
    const after = healthy && w === 'EMPTY' && !verdict[o].visible ? 1 : 0;
    const reach = healthy && !verdict[o].shadows ? 1 : 0;
    lines.push([f,k,w,o,a,b,r,before,after,reach].join(','));
    oldYes += before; newYes += after;
    shadowedOld += before && !reach ? 1 : 0;
    shadowedNew += after && !reach ? 1 : 0;
 }
const text = lines.join('\n')+'\n';
const counts = {
 matrix_sha256: createHash('sha256').update(text).digest('hex'),
 cases: lines.length,
 r188_structural_accepts: oldYes,
 r190_structural_accepts: newYes,
 r188_suppressed_callbacks: shadowedOld,
 r190_hidden_suppression_candidates: shadowedNew,
 native_wfp_runs: 0,
 no_direct_proof: false,
};
if (lines.length !== 480 || oldYes !== 60 || newYes !== 12 || shadowedOld !== 24 || shadowedNew !== 4)
 throw Error('independent oracle invariant failure');
process.stdout.write(JSON.stringify(counts)+'\n');
