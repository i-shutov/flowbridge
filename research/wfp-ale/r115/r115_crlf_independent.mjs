// Independent Node.js R115 oracle; user-mode/offline only.
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';

const expected='49506ca07145c18947a0845f2a1a63b3de1f54ec';
const source=execFileSync('git',['cat-file','blob',expected],{cwd:dirname(fileURLToPath(import.meta.url))});
function blob(b) {
  return createHash('sha1').update(Buffer.from('blob '+b.length+'\0','ascii')).update(b).digest('hex');
}
function canonical(b) {
  return Buffer.from(b.toString('latin1').replace(/\r\n/g,'\n'),'latin1');
}
function allow(b) { return blob(b)===expected || blob(canonical(b))===expected; }
const parts=source.toString('latin1').split('\n');
const mixed=Buffer.from(parts.slice(0,-1).map((s,i)=>s+(i%2===0?'\r\n':'\n')).join('')+parts.at(-1),'latin1');
const cases=[
  ['canonical_lf',source,true],
  ['all_crlf',Buffer.from(source.toString('latin1').replace(/\n/g,'\r\n'),'latin1'),true],
  ['mixed_lf_crlf',mixed,true],
  ['nul_appended',Buffer.concat([source,Buffer.from([0])]),false],
  ['truncated',source.subarray(0,-1),false],
  ['double_cr',Buffer.from(source.toString('latin1').replace(/\n/g,'\r\r\n'),'latin1'),false],
  ['bom',Buffer.concat([Buffer.from([239,187,191]),source]),false],
  ['stray_cr',Buffer.concat([source,Buffer.from([13])]),false],
];
for(let i=0;i<source.length;i+=151) {
  const changed=Buffer.from(source); changed[i]^=1;
  cases.push(['mutant_'+String(i).padStart(5,'0'),changed,false]);
}
assert.equal(cases.length,135);
const rows=cases.map(([label,data,want])=>{
  assert.equal(allow(data),want,label);
  return label+','+blob(data)+','+blob(canonical(data))+','+Number(allow(data));
});
const hash=createHash('sha256').update(rows.join('\n')+'\n','ascii').digest('hex');
assert.equal(hash,'0abcfc37018f43751e1e2d19419c4be048d075a0ae4abef56b338db7d2bfc8e3');
console.log('R115_MATRIX_SHA256='+hash);
console.log('PASS R115 NODE: 135 cases, independently reproduced');
console.log('NO_WINDOWS_OR_KERNEL_PROOF');
