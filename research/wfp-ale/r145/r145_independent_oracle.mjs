// R145 independent Node.js decision oracle, model-only, no network/WFP/driver.
import {createHash} from 'node:crypto';
let text = '', distribution = Object.create(null), rows = 0;
for (const family of [4,6]) for (const kind of ['LOCAL','SSH','DIRECT'])
for(let n=0;n<256;n++) {
  const bits=Array.from({length:8}, (_,j)=>(n>>(7-j))&1);
  const [selected, records, redirected, complete, reauth, live, write, prior]=bits;
  const chosen = selected===1;
  const allow = kind==='LOCAL' && redirected===1 && complete===1 && reauth===0 && live===1 && write===1;
  let verdict = !chosen ? 'UNMATCHED' : allow ? 'PERMIT_CANDIDATE' :
      (write===1 || prior===1) ? 'BLOCK_CANDIDATE' : 'PRESERVE_UNPROVEN';
  if(chosen && kind !== 'LOCAL' && verdict === 'PERMIT_CANDIDATE') throw Error('external permit');
  if(chosen && reauth && verdict === 'PERMIT_CANDIDATE') throw Error('reauth permit');
  distribution[kind+':'+verdict]=(distribution[kind+':'+verdict]||0)+1;
  text += family+'|'+kind+'|'+bits.join('')+'|'+verdict+'\n';
  rows++;
}
if(rows!==1536 || distribution['LOCAL:PERMIT_CANDIDATE']!==8 ||
   distribution['SSH:PERMIT_CANDIDATE'] || distribution['DIRECT:PERMIT_CANDIDATE']) throw Error('invariant');
const sorted=Object.fromEntries(Object.entries(distribution).sort(([a],[b])=>a.localeCompare(b, 'en')));
process.stdout.write(JSON.stringify({rows,sha256:createHash('sha256').update(text).digest('hex'),distribution:sorted,
 source_contract:'PINNED_R19',original_appid_propagation:'CONDITIONAL_UNPROVEN',
 native_wfp_executed:false,physical_ssh_proved:false,release_accepted:false})+'\n');
