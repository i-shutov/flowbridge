// Independent explicit-rule oracle, with no I/O or socket interaction.
import {createHash} from 'node:crypto';
const rules = [];
for (const family of [4, 6]) {
  rules.push({family, stage:'AUTH', tests:[['original','SELECTED'], ['protocol',6]]});
  rules.push({family, stage:'REDIRECT', tests:[['current','SELECTED'], ['protocol',6]]});
}
const names = ['SELECTED','SIBLING','ALIAS','MISSING'];
const rows=[];
let matched=0;
for (const family of [4,6]) for (const stage of ['AUTH','REDIRECT'])
  for (const protocol of [1,6,17,58]) for (const current of names) for (const original of names) {
    const flow={family,stage,protocol,current,original};
    const result=rules.some(r=>r.family===family && r.stage===stage &&
      r.tests.every(([field,value])=>flow[field]===value)) ? 'MATCH' : 'NO_MATCH';
    if (result==='MATCH') matched++;
    rows.push([family,stage,protocol,current,original,result].join('|'));
  }
if (rows.length!==256 || matched!==16) throw new Error('oracle mismatch');
for (const family of [4,6]) {
  for (const stage of ['AUTH','REDIRECT']) {
    if (rules.some(r=>r.family===family&&r.stage===stage && r.tests.every(([k,v])=>({protocol:17,current:'SELECTED',original:'SELECTED'})[k]===v)))
      throw new Error('UDP incorrectly matches');
  }
}
const digest=createHash('sha256').update(rows.join('\n')+'\n').digest('hex');
console.log('states',rows.length,'matched',matched,'not_matched',rows.length-matched);
console.log('matrix_sha256',digest);
