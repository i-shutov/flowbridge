// R101 independent condition oracle. Model only; no external I/O or Windows API.
import { createHash } from 'node:crypto';

function oracle(rec, original, policy, callout, spent, local, ready) {
  if (!rec) return 'NO_WFP_RECORD';
  if (!ready) return 'SSH_UNAVAILABLE';
  if (!original) return 'ORIGINAL_APPID_NOT_SELECTED_UNPROVED';
  const requires = Boolean(policy && callout);
  if (!requires) return 'AUTH_ENFORCEMENT_UNPROVED';
  const admissible = Boolean(!spent && local);
  return admissible ? 'SYNTHETIC_AUTH_ALLOW_NOT_WINDOWS_PASS' : 'R19_AUTH_CALLBACK_BLOCK';
}

const entries=[];
for (const family of [4,6]) {
  for (let mask=0;mask<128;mask++) {
    // Mirror Python itertools.product: first bit is the most significant.
    const xs=Array.from({length:7},(_,i)=>Number(Boolean(mask & (1<<(6-i)))));
    entries.push(`${[family,...xs].join(';')};${oracle(...xs)}`);
  }
}
const matrix=entries.join('\n')+'\n';
const counts=new Map();
for(const row of entries) {
  const label=row.split(';').at(-1);
  counts.set(label,(counts.get(label)??0)+1);
}
if(entries.length!==256 || new Set(entries).size!==256)throw new Error('matrix incorrect');
if(oracle(1,1,1,1,1,0,1)!=='R19_AUTH_CALLBACK_BLOCK')throw new Error('witness missed');
if(oracle(1,1,1,1,0,1,1)!=='SYNTHETIC_AUTH_ALLOW_NOT_WINDOWS_PASS')throw new Error('positive synthetic control missed');
console.log('rows',entries.length,'sha256',createHash('sha256').update(matrix).digest('hex'));
console.log('counts',[...counts.entries()].sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>`${k}=${v}`).join(','));
console.log('conditional_witness',`4;1;1;1;1;1;0;1;${oracle(1,1,1,1,1,0,1)}`);
