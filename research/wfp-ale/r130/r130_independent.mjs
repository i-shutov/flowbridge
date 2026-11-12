// Independent exact-byte and supplied-result audit, not a Rust logic emulator.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
const here=dirname(fileURLToPath(import.meta.url));
const root=resolve(here,'../../..');
const pins=JSON.parse(readFileSync(resolve(here,'r130_source_pins.json'),'utf8'));
const hash=(alg,b)=>createHash(alg).update(b).digest('hex');
const valid=(b,p)=>hash('sha1',Buffer.concat([Buffer.from(`blob ${b.length}\0`),b]))===p.git_blob && hash('sha256',b)===p.sha256;
let accepted=0,rejected=0,tests=0;
for(const p of pins.sources){
 const b=readFileSync(resolve(root,p.path));if(!valid(b,p))throw Error('source mismatch '+p.path);accepted++;
 tests+=(b.toString().match(/#\[test\]/g)||[]).length;
 for(const bit of [1,2,128])for(const index of [0,Math.floor(b.length/2),b.length-1]){
  const v=Buffer.from(b);v[index]^=bit;if(valid(v,p))throw Error('mutant accepted');rejected++;
 }
 for(const v of [Buffer.from(b.toString().replaceAll('\n','\r\n')),Buffer.concat([Buffer.from([239,187,191]),b]),b.subarray(0,b.length-1)]){
  if(valid(v,p))throw Error('encoding/truncation accepted');rejected++;
 }
}
const rows=readFileSync(resolve(here,'R129_OWNER_OBSERVATION.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
if(rows.length!==5||tests!==60)throw Error('cardinality');
const names=['auth_connect_v4','auth_connect_v6','connect_redirect_v4','connect_redirect_v6'];
for(let i=0;i<4;i++){
 const r=rows[i];
 if(r.rule!==names[i]||r.key!==`1649f03${i}-25b3-4e01-9ca1-5ca803010019`||r.api_code!==0x80320003||r.api_code_hex!=='0x80320003'||r.pointer_present!==false||r.observation!=='NOT_FOUND_RETURNED')throw Error('observation mismatch');
}
const t=rows[4];
if(t.status!=='NOT_FOUND_OBSERVED'||t.close_code!==0||t.diagnostic_exit!==4||t.atomic_snapshot!==false)throw Error('summary');
if(rows.some(r=>r.kernel_proof!==false||r.no_direct_proof!==false))throw Error('false proof');
console.log(JSON.stringify({sources:pins.sources.length,accepted_exact:accepted,rejected_mutations:rejected,rust_execution:'NOT_RUN'}));
