// Independent Node oracle: all object/shape/kernel-registration combinations.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,join} from 'node:path';
const rust=readFileSync(join(dirname(fileURLToPath(import.meta.url)),'..','r93','r93_readonly_policy_inventory.rs'),'utf8');
if(!rust.includes('FWPM_CALLOUT_FLAG_REGISTERED: u32 = 0x00040000'))throw Error('flag missing');
if(!rust.includes('shape_complete && registered_snapshot_complete'))throw Error('gate missing');
const rows=[];let old=0,strict=0,oldFalse=0;
for(let objects=0;objects<256;objects++){
  for(let shape=0;shape<16;shape++){
    for(let reg=0;reg<16;reg++){
      const before=Number((objects&255)===255&&(shape&15)===15);
      const after=Number(before===1&&(reg^15)===0);
      old+=before;strict+=after;oldFalse+=before*(1-after);
      rows.push([objects.toString(16).padStart(3,'0'),shape.toString(16),reg.toString(16),before,after].join(','));
    }
  }
}
if(rows.length!==65536||old!==16||strict!==1||oldFalse!==15)throw Error('unexpected case count');
console.log('R94_MATRIX_SHA256',createHash('sha256').update(rows.join('\n')+'\n').digest('hex'));
console.log('ROWS',rows.length,'OLD',old,'NEW',strict,'LEGACY_FALSE_POSITIVES',oldFalse);
