// Independent structural audit: deterministic, no PowerShell/WFP execution.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const p=readFileSync(new URL('./R210_R203v6_PINNED_R209.diff',import.meta.url),'utf8');
const sha='9ead09f9001c02444975fab37caee03ed4e55308';
let count=0;function ok(name,f){f();count++;console.log('PASS '+name);}
ok('single exact commit',()=>assert.equal((p.match(/\$r209Commit = '/g)||[]).length,1));
ok('pinned SHA',()=>assert.ok(p.includes(`$r209Commit = '${sha}'`)));
ok('three exact paths',()=>assert.equal((p.match(/^\+    'research\/wfp-ale\/r209\//gm)||[]).length,3));
ok('three SHA1 blobs',()=>assert.equal((p.match(/^\+    'research\/wfp-ale\/r209\/[^']+' = '[a-f0-9]{40}'/gm)||[]).length,3));
ok('path-count guard',()=>assert.ok(p.includes('$changes.Count -ne $r209Blobs.Count')));
ok('per-entry membership guard',()=>assert.ok(p.includes('$r209Blobs.Contains($entry)')));
ok('per-entry blob guard',()=>assert.ok(p.includes('$blob -cne $r209Blobs[$entry]')));
ok('no generic r209 allowlist',()=>assert.ok(!p.includes("'research/wfp-ale/r209/'")));
ok('legacy three-prefix gate unchanged',()=>assert.ok(p.includes("$allowedPrefix = @('research/wfp-ale/r203/','research/wfp-ale/r204/','research/wfp-ale/r205/')")));
console.log(`${count}/${count} PASS (patch audit, not native execution)`);
