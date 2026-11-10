// R97 independent enumerator for layer-pair equality vs exact expected layer.
// Pure Node standard library, no WFP, network or host mutation.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(here, '../r93/r93_readonly_policy_inventory.rs'), 'utf8');
const policy = readFileSync(resolve(here, '../kernel-r19/policy_windows.rs'), 'utf8');
if (!source.includes('fv.layer_key == cv.applicable_layer') ||
    !policy.includes('fn layer(r:Rule)->GUID') ||
    !['FWPM_LAYER_ALE_AUTH_CONNECT_V4','FWPM_LAYER_ALE_AUTH_CONNECT_V6',
       'FWPM_LAYER_ALE_CONNECT_REDIRECT_V4','FWPM_LAYER_ALE_CONNECT_REDIRECT_V6']
       .every(token => policy.includes(token))) throw Error('source contract mismatch');
const layer = ['AUTH_V4','AUTH_V6','REDIRECT_V4','REDIRECT_V6','OTHER'];
const output = [];
let oldPass = 0, strictPass = 0, falsePass = 0;
for (let i = 0; i < 4; ++i) {
  const expected = layer[i];
  for (const x of layer) for (const y of layer) {
    const previous = x === y ? 1 : 0;
    const candidate = [x,y].every(v => v === expected) ? 1 : 0;
    if (previous) oldPass++;
    if (candidate) strictPass++;
    if (previous && !candidate) falsePass++;
    output.push([i,expected,x,y,previous,candidate].join(','));
  }
}
if ([output.length,oldPass,strictPass,falsePass].join(',') !== '100,20,4,16')
  throw Error('unexpected matrix');
const digest = createHash('sha256').update(output.join('\n')+'\n').digest('hex');
console.log(`cases=${output.length} r95_gate_accepts=${oldPass} strict_layer_accepts=${strictPass} false_positives=${falsePass}`);
console.log('matrix_sha256='+digest);
