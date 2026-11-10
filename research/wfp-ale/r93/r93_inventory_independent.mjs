// Independent JS oracle. Does not load Python nor execute Windows APIs.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {dirname,join} from 'node:path';
const root=dirname(fileURLToPath(import.meta.url));
const src=readFileSync(join(root,'r93_readonly_policy_inventory.rs'),'utf8');
const original=readFileSync(join(root,'..','kernel-r19','policy_windows.rs'),'utf8');
if(!src.includes('FwpmFilterGetByKey0')||!src.includes('FwpmCalloutGetByKey0'))throw Error('missing read API');
if(!src.includes('kernel_origin_proof\\\":false')||!src.includes('continuous_enforcement_proof\\\":false'))throw Error('misleading proof');
// Derive keys independently from the actual R19 filter_key source, not the Python oracle.
const found=original.match(/0x([0-9a-f]{8})_25b3_4e01_9ca1_5ca803010019\+\(\(n as u128\)<<96\)/);
if(!found)throw Error('filter key layout changed');
const base=Number.parseInt(found[1],16);
for(let n=0;n<4;n++)if((base+n)!==(0x1649f030+n))throw Error('filter IDs diverged');
const cases=[];
for(let mask=0;mask<256;mask++){
  for(let shape=0;shape<16;shape++){
    // Unlike Python's all() implementation, deliberately bitwise fail-closed.
    const outcome=+(mask===0xff&&shape===0xf);
    cases.push(`${mask.toString(16).padStart(3,'0')},${shape.toString(16)},${outcome}`);
  }
}
const csv=cases.join('\n')+'\n';
const sha=createHash('sha256').update(csv).digest('hex');
console.log('R93_MATRIX_SHA256',sha);
console.log('R93_ROWS',cases.length,'POSITIVE',cases.filter(x=>x.endsWith(',1')).length);
