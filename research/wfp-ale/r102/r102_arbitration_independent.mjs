// Independent Node oracle. No Windows APIs, sockets, kernel or BFE operations.
import { createHash } from 'node:crypto';
const rows=[];
const labels=['v4','v6'];
const stages=['AUTH_CONNECT','CONNECT_REDIRECT'];
const actions=['PERMIT','BLOCK','CONTINUE'];
let counts={shadowPermit:0,shadowBlock:0,reached:0};
for(let f=0; f<2; f++) for(let l=0;l<2;l++) for(let presence=0;presence<=1;presence++)
 for(let matching=0;matching<=1;matching++) for(const action of actions){
    // Filter arbitration evaluates higher-weight matching filters first;
    // a terminating PERMIT/BLOCK skips the remaining ones in that sublayer.
    const priorStops = Boolean(presence & matching) && (action !== 'CONTINUE');
    let result;
    if(!priorStops){result='FLOWBRIDGE_CALLOUT_REACHED_IN_MODEL';counts.reached++;}
    else if(action === 'PERMIT'){result='SHADOWED_BY_PERMIT';counts.shadowPermit++;}
    else {result='SHADOWED_BY_BLOCK';counts.shadowBlock++;}
    rows.push([labels[f],stages[l],presence,matching,action,result].join('|'));
 }
if(rows.length!==48 || counts.shadowPermit!==4 || counts.shadowBlock!==4 || counts.reached!==40)
 throw Error(JSON.stringify({rows:rows.length,counts}));
const sha=createHash('sha256').update(rows.join('\n')+'\n','utf8').digest('hex');
console.log('R102 INDEPENDENT: 48 deterministic cases; shadowed=8, reached=40; PASS');
console.log('MATRIX_SHA256='+sha);
console.log('WITNESS='+rows.find(x=>x.endsWith('|SHADOWED_BY_PERMIT')));
console.log('LIMIT=abstract same-sublayer collision; no Windows/WFP observation');
