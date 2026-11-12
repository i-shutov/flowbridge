// R126 independent Node.js oracle: no WFP, native code, sockets or modules except crypto.
import {createHash} from 'node:crypto';
let skipped=0, candidate=0, veto=0, uplink=0, outside=0;
let sha=createHash('sha256');
for (let mask=0;mask<4096;mask++) {
  const selected = (mask & 1) !== 0;
  const tcp = (mask & 2) !== 0;
  const loop = (mask & 4) !== 0;
  const redirect = (mask & 8) !== 0;
  const brokerTarget = (mask & 16) !== 0;
  const originalDest = (mask & 32) !== 0;
  const processSelected = (mask & 64) !== 0;
  const endpoint = (mask & 128) !== 0;
  const initial = (mask & 256) !== 0;
  const currentBroker = (mask & 512) !== 0;
  const sshUp = (mask & 1024) !== 0;
  let verdict;
  if (!selected || !tcp) { verdict='NO_MATCH'; skipped++; }
  else if (loop && redirect && brokerTarget && originalDest && processSelected && endpoint && initial && sshUp) {
    verdict='PERMIT_CANDIDATE';candidate++;
  } else {verdict='BLOCK_CANDIDATE'; veto++;}
  if (selected && tcp && currentBroker && !processSelected && !loop) {
    if (verdict!=='BLOCK_CANDIDATE') throw new Error('proxy-flow counterexample '+mask);
    uplink++;
  }
  if(!selected && tcp) {if(verdict!=='NO_MATCH')throw new Error('no-match '+mask); outside++;}
  sha.update(String(mask).padStart(4,'0')+'|'+verdict+'\n','ascii');
}
if(candidate!==4||uplink!==128)throw new Error('unexpected counts');
const result={cases:4096,counts:{NO_MATCH:skipped, PERMIT_CANDIDATE:candidate, BLOCK_CANDIDATE:veto},
 proxy_leg_must_block_in_model:uplink, unselected_original_no_filter:outside,matrix_sha256:sha.digest('hex')};
console.log('R126_MATRIX='+JSON.stringify(result));
