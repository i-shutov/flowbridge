// Independent Node.js oracle, offline, no WFP, no network, no driver.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const data=fs.readFileSync(path.join(root,'r103','r103_readonly_arbitration_inventory.rs'));
const ps=fs.readFileSync(path.join(root,'r112','R112_WINDOWS_NATIVE_READONLY_CHECK.ps1'),'utf8');
const pin='06c677b484ef2cf5fa0330f819524dfa6b52e55a';
const old='49506ca07145c18947a0845f2a1a63b3de1f54ec';
function blob(b){return createHash('sha1').update(Buffer.from('blob '+b.length+'\0','ascii')).update(b).digest('hex');}
function canonicalize(b){const arr=[];for(let i=0;i<b.length;i++){if(b[i]===13&&b[i+1]===10)continue;arr.push(b[i]);}return Buffer.from(arr);}
assert.equal(blob(data),pin);
assert.equal([...ps.matchAll(/^\$expectedGitBlob\s*=\s*'([0-9a-f]{40})'\s*$/gm)].map(x=>x[1]).join(','),pin);
assert.notEqual(pin,old);
const crlf=Buffer.from(data.toString('utf8').replaceAll('\n','\r\n'),'utf8');
assert.equal(blob(canonicalize(crlf)),pin);
let rejected=0;
for(let i=0;i<100;i++){
  const p=Math.trunc((i*data.length)/100), mut=Buffer.from(data);mut[p]^=1;
  assert.notEqual(blob(canonicalize(mut)),pin);rejected++;
}
for(const x of [data.subarray(0,-1),Buffer.concat([data,Buffer.from('\n')]),Buffer.concat([Buffer.from([239,187,191]),data])]) {
  assert.notEqual(blob(canonicalize(x)),pin);rejected++;
}
assert.ok(ps.includes('if ($normalizedBlob -ne $expectedGitBlob)'));
assert.ok(ps.includes('$resolved = $canonicalPath'));
console.log(JSON.stringify({tag:'R124_INDEPENDENT',source_blob:pin,old_blob:old,crlf_equivalent:true,negative_mutations_rejected:rejected,local_only:true,native_windows_run:false,kernel_proof:false}));
