// R201 independent source contract audit of a clean-room Rust state model.
// No compile, runtime WFP, network, driver, or proof of Windows ABI.
import {readFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
const source=readFileSync(join(dirname(fileURLToPath(import.meta.url)),'selective_ledger.rs'),'utf8');
const lines=[
 ['qualified-only birth storage', /let Some\(role\) = self\.pins\.role\(&id\.canonical_exe\) else \{return Decision::Ignored;\}/],
 ['no unrelated PID collision promotion', /self\.live\.iter\(\)\.any\(\|x\|x\.identity\.pid == id\.pid\) \{return self\.stop\(\)/],
 ['exact opaque object on death', /self\.live\[index\]\.identity\.process_ref != process_ref \{return self\.stop\(\)/],
 ['live slot removed only after death object check', /let departed = self\.live\.remove\(index\)/],
 ['bounded incarnation memory', /self\.history\.len\(\) == self\.max_history/],
 ['bounded endpoint tombstones', /self\.endpoints\.len\(\) == self\.max_endpoints/],
 ['endpoint reuse terminal', /self\.endpoints\.contains\(&endpoint\).*return self\.stop\(\)/s],
 ['TCP+dual-family scope', /!matches!\(family, 4 \| 6\) \|\| protocol != 6/],
 ['origin AppId + redirect + reauth gate', /!redirected \|\| reauthorize \|\| original_appid != self\.pins\.selected/],
 ['generation and origin match for receipt', /t\.generation == owner\.generation && t\.endpoint == endpoint/],
 ['single-use terminal claim', /let t = self\.tickets\.remove\(idx\)/],
 ['health-loss kills live tickets', /self\.stopped = true;\s*self\.tickets\.clear\(\)/],
];
for(const [label,re] of lines) assert.match(source,re,label);
assert.doesNotMatch(source,/extern\s*"|unsafe\s*\{|std::net|std::process|std::fs|windows_sys|winapi|Fwpm|Fwps|WSAIoctl|TcpStream|UdpSocket/, 'no executable kernel/Win32/network/file path');
assert.match(source,/#\[cfg\(test\)\]/,'standalone Rust unit tests included');
const mutation=source.replace('|| protocol != 6', '|| protocol == 6');
assert.doesNotMatch(mutation,lines[7][1], 'mutation sensitivity: accidental UDP gate inversion detected');
console.log('R201 source predicates '+lines.length+'/12 PASS; forbidden API check PASS; mutation detection PASS; uncompiled Rust');
