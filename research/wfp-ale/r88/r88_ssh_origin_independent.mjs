// Independent Node decision table: no Python import, no OS/network calls.
import {createHash} from 'node:crypto';
const F=['4','6'],A=['SELECTED','BROKER','UNKNOWN'],R=['LOOPBACK','REMOTE'];
const B=[0,1]; const lines=[]; const counts={};
for(const f of F)for(const a of A)for(const r of R)
 for(const d of B)for(const m of B)for(const w of B)for(const t of B){
  let verdict;
  switch(a){
    case 'UNKNOWN': verdict='UNKNOWN_FILTER_MATCH';break;
    case 'BROKER': verdict='FILTER_NOT_SELECTED';break;
    default:
      if(w===0) verdict='RIGHTS_UNPROVEN';
      else if(r==='REMOTE'||d===0||m===0||t===0) verdict='SOURCE_BLOCK';
      else verdict='AUTH_CANDIDATE';
  }
  lines.push([f,a,r,d,m,w,t,verdict].join('|')+'\n');
  counts[verdict]=(counts[verdict]||0)+1;
}
const digest=createHash('sha256').update(lines.join(''),'utf8').digest('hex');
const expected='6764f67ccb750eee4e619ad31ab770d721aec475e7b920afb07e80965e39a335';
if(lines.length!==192 || digest!==expected)throw Error('R88 independent oracle mismatch');
console.log('MATRIX',JSON.stringify({cases:lines.length,counts,sha256:digest}));
