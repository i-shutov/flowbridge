#!/usr/bin/env node
// Independent state engine. Calls Python for comparison only, never imports its logic.
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {dirname,join} from 'node:path';
const alphabet=['BFE_SESSION_LOST','BFE_SERVICE_RESTART','HEARTBEAT','PROBE','SELECTED_V4','SELECTED_V6','SSH_LOST','BROKER_EXIT'];
function run(seq){
 let bfe=1,filters=1,lease=1,broker=1,reported=1,v4=0,v6=0,unrevoked=0,probed=0;
 for(const e of seq){switch(e){
  case 'BFE_SESSION_LOST':bfe=0;filters=0;break;
  case 'BFE_SERVICE_RESTART':bfe=1;break;
  case 'HEARTBEAT':reported=lease&&broker;break;
  case 'PROBE':probed=1;if(!filters){reported=0;lease=0;}break;
  case 'SELECTED_V4':if(!filters){v4++;unrevoked+=+!!reported;}break;
  case 'SELECTED_V6':if(!filters){v6++;unrevoked+=+!!reported;}break;
  case 'SSH_LOST':lease=0;reported=0;break;
  case 'BROKER_EXIT':broker=0;filters=0;lease=0;reported=0;break;
  default:throw Error('bad event '+e);
 }}return{filters,reported,v4,v6,unrevoked,probed};
}
function oracle(){
 const c={traces:0,uncovered_v4_traces:0,uncovered_v6_traces:0,uncovered_while_reported_traces:0,bfe_missing_reported_traces:0,probe_with_uncovered_traces:0};
 function walk(events,depth){const s=run(events);c.traces++;
  if(s.v4)c.uncovered_v4_traces++;
  if(s.v6)c.uncovered_v6_traces++;
  if(s.unrevoked)c.uncovered_while_reported_traces++;
  if(!s.filters&&s.reported)c.bfe_missing_reported_traces++;
  if(s.probed&&(s.v4+s.v6))c.probe_with_uncovered_traces++;
  if(depth<4)for(const a of alphabet)walk(events.concat(a),depth+1);
 }walk([],0);return c;
}
const py=join(dirname(fileURLToPath(import.meta.url)),'r160_repo.py');
const p=spawnSync('python3',['-B',py,'--matrix'],{encoding:'utf8'});
if(p.status!==0)throw Error(p.stderr||'python failed');
const expected=oracle(),actual=JSON.parse(p.stdout);
for(const key of Object.keys(expected))if(expected[key]!==actual[key])throw Error(key+': JS='+expected[key]+' Python='+actual[key]);
if(actual.traces!==4681)throw Error('bad exhaustive range');
console.log(JSON.stringify({status:'PASS',checked:4681,counts:actual},null,2));
