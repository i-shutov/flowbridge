#!/usr/bin/env node
// R163 independent Node.js decision oracle.  No shared Python model imported.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import process from 'node:process';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {dirname,join} from 'node:path';

const here=dirname(fileURLToPath(import.meta.url));
const py=join(here,'r163_egress_collision.py');
const observed=JSON.parse(process.argv[2] ? fs.readFileSync(process.argv[2],'utf8')
  : execFileSync('python3',[py,'--matrix'],{encoding:'utf8',maxBuffer:8*1024*1024}));
let rows=[];
const counts={NOT_INVOKED:0,PRESERVE_CONTINUE:0,BLOCK:0,PERMIT:0};
let id=0;
for(const family of [4,6])
 for(const orig_app of ['selected','broker','sibling'])
  for(const remote of ['loopback','ssh_peer','other'])
   for(const policy of [false,true])
    for(const records_attached of [false,true])
     for(const redirect_flag of [false,true])
      for(const reauth of [false,true])
       for(const write_right of [false,true])
        for(const ticket of [false,true]) {
         // Independent expression: BFE selection first, rights second,
         // auth request predicates after.  Records do not dictate AppId.
         let decision;
         if(!policy || orig_app==='broker' || orig_app==='sibling') decision='NOT_INVOKED';
         else if(!write_right) decision='PRESERVE_CONTINUE';
         else if(remote==='loopback' && redirect_flag && !reauth && ticket) decision='PERMIT';
         else decision='BLOCK';
         rows.push({id:id++,family,orig_app,remote,policy,records_attached,
            redirect_flag,reauth,write_right,ticket,decision});
         counts[decision]++;
        }
assert.equal(observed.kind,'R163_CONDITIONAL_AUTH_EGRESS_COLLISION');
assert.equal(observed.count,rows.length);
assert.deepEqual(observed.counts,counts);
assert.deepEqual(observed.rows,rows);
assert.equal(observed.source_pins['research/wfp-ale/kernel-r19/kernel/src/redirect.rs'],
 'a093f049d162987981a957aac90db1014bc6ff09');
assert.equal(observed.source_pins['research/wfp-ale/kernel-r19/policy_windows.rs'],
 'acf60334320d970f58af3349ee75fbaa59826602');
console.log(JSON.stringify({result:'PASS',compared:rows.length,counts,divergences:0,
  limitation:'Conditional on runtime WFP ALE_ORIGINAL_APP_ID; no kernel observation'}));
