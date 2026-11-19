#!/usr/bin/env node
// Independent scenario oracle. Only models WFP contract and R19's source-level
// absence of a prior-version guard. Does not observe actual packets or sockets.
import {createHash} from 'node:crypto';
const scenarios=[];
for(const family of [4,6]) for(const predecessor of ['none','remote','token'])
for(const record of ['absent','self','other']) for(const auth_destination of ['initial','current']) {
  // The driver sees current request destination. The app's initial destination
  // need not equal it if another filter changed remoteAddressAndPort first.
  const before=String(family)+':original';
  const visible=predecessor==='remote'?String(family)+':modified':before;
  const acceptedSocketAttribution=auth_destination==='initial'?before:visible;
  let outcome;
  switch(record){
    case 'self':outcome='continue_no_ticket';break;
    case 'other':outcome='block_no_ticket';break;
    default:outcome=visible===acceptedSocketAttribution?'local_attest_candidate':'auth_block';
  }
  scenarios.push({family,predecessor,record,auth_destination,outcome,
    original_preserved:visible===before,
    evidence_gap:outcome==='local_attest_candidate'&&visible!==before});
}
if(scenarios.length!==36)throw Error('matrix wrong');
const gap=scenarios.filter(x=>x.evidence_gap);
if(gap.length!==2||gap.some(x=>x.predecessor!=='remote'||x.record!=='absent'||x.auth_destination!=='current'))throw Error('gap logic changed');
const wire=scenarios.map(x=>JSON.stringify(Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b))))+'\n').join('');
const sha256=createHash('sha256').update(wire).digest('hex');
console.log(JSON.stringify({cases:scenarios.length,conditional_gap:gap.length,sha256,source_guard:'NOT_RUN'}));
