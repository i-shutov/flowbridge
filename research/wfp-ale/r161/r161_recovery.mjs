#!/usr/bin/env node
// Independent event evaluator; does not import Python model or source constants.
import {spawnSync} from 'node:child_process';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
const actions=['ARM','STOP','BROKER_EXIT','BROKER_RESTART','LEASE_TIMEOUT_CHECK','BFE_SESSION_LOST','POLICY_REINSTALL','PING'];
function step(seq){
 let configured=0,armed=0,lost=0,broker=1,bfe=1,epoch=0,owner=-1,ok=0,denied=0,pingOk=0,pingNoBfe=0,reinstallTerminal=0;
 for(const a of seq){
  if(a==='ARM'){if(configured||!broker||lost)denied++;else{configured=1;armed=1;owner=epoch;ok++;}}
  else if(a==='STOP'){if(configured&&broker&&epoch===owner){armed=0;lost=1;}}
  else if(a==='BROKER_EXIT'){if(broker&&configured&&epoch===owner){armed=0;lost=1;}broker=0;}
  else if(a==='BROKER_RESTART'){if(!broker){broker=1;epoch++;}}
  else if(a==='LEASE_TIMEOUT_CHECK'){if(configured&&armed){armed=0;lost=1;}}
  else if(a==='BFE_SESSION_LOST'){bfe=0;}
  else if(a==='POLICY_REINSTALL'){bfe=1;if(configured&&lost)reinstallTerminal++;}
  else if(a==='PING'){if(armed&&!lost&&broker&&epoch===owner) {pingOk++;pingNoBfe+=+(!bfe);}}
  else throw Error('unknown event');
  if(ok>1||(lost&&armed))throw Error('invariant');
 }
 return{configured,armed,lost,bfe,denied,pingOk,pingNoBfe,reinstallTerminal};
}
const out={traces:0,terminal:0,rejected_rearm:0,reinstalled_terminal:0,bfe_missing_ping_ok:0,configured_and_not_armed:0};
function visit(seq,depth){
 const s=step(seq);out.traces++;
 out.terminal+=+(!!s.configured&&!!s.lost);
 out.rejected_rearm+=+(!!s.lost&&s.denied>0);
 out.reinstalled_terminal+=+(s.reinstallTerminal>0);
 out.bfe_missing_ping_ok+=+(s.pingNoBfe>0);
 out.configured_and_not_armed+=+(!!s.configured&&!s.armed);
 if(depth<5)for(const a of actions)visit([...seq,a],depth+1);
}
visit([],0);
const python=join(dirname(fileURLToPath(import.meta.url)),'r161_recovery.py');
const p=spawnSync('python3',['-B',python,'--matrix'],{encoding:'utf8'});
if(p.status!==0)throw Error(p.stderr);
const actual=JSON.parse(p.stdout);
for(const k of Object.keys(out))if(out[k]!==actual[k])throw Error(`mismatch ${k}: JS=${out[k]} Python=${actual[k]}`);
if(out.traces!==37449)throw Error('incomplete enumeration');
console.log(JSON.stringify({status:'PASS',independent_trace_comparison:out.traces,results:out}));
