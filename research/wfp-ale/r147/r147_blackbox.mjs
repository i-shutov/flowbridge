// Independent case generation + black-box execution of the REAL Python verifier.
// No emulation of validate_blueprint; all decisions come from its actual CLI.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const python = process.env.PYTHON || 'python';
const compiler = resolve(here, '../r143/r143_policy_compiler.py');
const verifier = resolve(here, 'r147_blueprint_verify.py');
// Payload hash excludes blueprint_sha256; file hash includes it. Both are pinned.
const GOLDEN = '0709309dd0f1b4b79e1a3bda4940a03bde30be5c5702c3a16065b388ebf3873e';
const GOLDEN_FILE = 'f1f08d056e88010fee2cf9bc4f47ea6e3dfc2af22231117a98bffda62f605ebb';
function run(args, input) {
  const p = spawnSync(python, args, {input, encoding:'utf8', timeout:120000,
    maxBuffer:8*1024*1024, windowsHide:true, shell:false});
  assert.ifError(p.error);
  assert.equal(p.signal, null, 'child terminated by signal');
  return p;
}
const origin = run(['-B', compiler]);
assert.equal(origin.status, 0, origin.stderr);
assert.equal(createHash('sha256').update(origin.stdout).digest('hex'), GOLDEN_FILE);
const golden = JSON.parse(origin.stdout);
assert.equal(golden.blueprint_sha256, GOLDEN, 'unexpected design; do not repin');
function sorted(v) {
  if (Array.isArray(v)) return v.map(sorted);
  if (v !== null && typeof v === 'object')
    return Object.fromEntries(Object.keys(v).sort().map(k => [k, sorted(v[k])]));
  return v;
}
function rehash(v) {
  if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
    delete v.blueprint_sha256;
    const bytes = JSON.stringify(sorted(v), null, 2) + '\n';
    v.blueprint_sha256 = createHash('sha256').update(bytes).digest('hex');
  }
  return v;
}
assert.equal(rehash(structuredClone(golden)).blueprint_sha256, GOLDEN);
const paths = [];
function walk(v, path=[]) {
  paths.push([path, v]);
  if (v !== null && typeof v === 'object')
    for (const [k, item] of Object.entries(v))
      walk(item, [...path, Array.isArray(v) ? Number(k) : k]);
}
walk(golden);
const cases = [];
function add(label, value, expected=false, raw=null) {
  cases.push({label, expected, raw:raw ?? JSON.stringify(value)});
}
add('pristine', golden, true);
add('pristine_rehashed', rehash(structuredClone(golden)), true);
add('pristine_whitespace', null, true, '  ' + JSON.stringify(golden) + '  ');
const replacements = [null, false, true, 0, 1, -1, '', 'false', 'MUTATED', [], {}];
for (const [path, old] of paths) {
  for (let j=0; j<replacements.length; j++) {
    const next = replacements[j];
    if (JSON.stringify(old) === JSON.stringify(next)) continue;
    let value = structuredClone(golden);
    if (!path.length) value = structuredClone(next);
    else {
      let parent=value;
      for(const key of path.slice(0,-1)) parent=parent[key];
      parent[path.at(-1)]=structuredClone(next);
    }
    if (path[0] !== 'blueprint_sha256') rehash(value);
    add('replace:' + JSON.stringify(path) + ':' + j, value);
  }
  if (path.length) {
    const value=structuredClone(golden); let parent=value;
    for(const key of path.slice(0,-1)) parent=parent[key];
    if (Array.isArray(parent)) parent.splice(path.at(-1),1);
    else delete parent[path.at(-1)];
    if (path[0] !== 'blueprint_sha256') rehash(value);
    add('delete:' + JSON.stringify(path),value);
  }
  if (old !== null && typeof old === 'object' && !Array.isArray(old)) {
    const value=structuredClone(golden); let obj=value;
    for(const key of path) obj=obj[key];
    obj.UNEXPECTED_AUTHORITY=true;
    rehash(value); add('extra:' + JSON.stringify(path),value);
  }
}
const compact=JSON.stringify(golden);
add('duplicate_schema', null, false, compact.replace('"schema":1','"schema":1,"schema":1'));
add('float_schema', null, false, compact.replace('"schema":1','"schema":1.0'));
add('nan_schema', null, false, compact.replace('"schema":1','"schema":NaN'));
add('infinity_schema', null, false, compact.replace('"schema":1','"schema":1e9999'));
add('bom',null,false,'\ufeff'+compact);
add('trailing_document',null,false,compact+' {}');
add('blank',null,false,' ');
const rows=cases.map(x=>x.raw+'\n').join('');
assert(cases.length<4096,'campaign exceeds record budget');
assert(Buffer.byteLength(rows)<16*1024*1024,'campaign exceeds byte budget');
const hashes=[];
for (const optimized of [false,true]) {
  const p=run([...(optimized?['-O']:[]),'-B',verifier,'--jsonl','-'],rows);
  assert.equal(p.status,2,'mixed campaign must reject, never exit 0');
  assert.equal(p.stderr,'','unexpected verifier stderr');
  const output=p.stdout.trim().split('\n').map(JSON.parse);
  const summary=output.pop();
  assert.equal(output.length,cases.length,'dropped or extra records');
  const hash=createHash('sha256');
  let accepted=0;
  for(let i=0;i<cases.length;i++) {
    const actual=output[i], expected=cases[i];
    assert.equal(actual.record,i);
    assert.equal(actual.design_valid,expected.expected,expected.label);
    assert.equal(actual.native_wfp_executed,false);
    assert.equal(actual.release_accepted,false);
    assert.equal(actual.no_direct_proved,false);
    accepted+=Number(actual.design_valid);
    hash.update(`${expected.label}|${Number(actual.design_valid)}\n`);
  }
  assert.equal(summary.summary,true);
  assert.equal(summary.records,cases.length);
  assert.equal(summary.accepted_designs,accepted);
  assert.equal(summary.rejected,cases.length-accepted);
  assert.equal(summary.native_wfp_executed,false);
  assert.equal(summary.release_accepted,false);
  const sha256=hash.digest('hex'); hashes.push(sha256);
  console.log(JSON.stringify({optimized,states:cases.length,accepted,
    rejected:cases.length-accepted,sha256,native_wfp_executed:false,release_accepted:false}));
}
assert.equal(hashes[0],hashes[1],'optimization changed actual acceptance');
