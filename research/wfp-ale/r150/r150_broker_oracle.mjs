// Independent read-only Node oracle for R150 broker-bootstrap scenarios.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const roleBroker='opaque:FlowBridgeBroker.exe', roleSelected='opaque:Selected.exe', other='opaque:another.exe';
function Monitor(type){return {type,broker:new Map(),selected:new Map(),armed:false};}
function start(m,pid,epoch,pointer,tag){
 if(tag===roleBroker && m.type!=='selected'){m.broker.set(pid,[epoch,pointer]);return 'BROKER_TRACKED';}
 if(m.armed && tag===roleSelected){m.selected.set(pid,[epoch,pointer]);return 'SELECTED_TRACKED';}
 return 'SKIPPED';
}
function activate(m,pid,epoch,pointer,image){
 const rec=m.broker.get(pid);
 if(!rec || rec[0]!==epoch || rec[1]!==pointer)return 'ARM_DENY_UNPROVEN_BROKER';
 if(image===roleBroker||m.armed)return 'ARM_DENY_INVALID';
 m.armed=true;return 'ARM_MODEL_ONLY';
}
function check(m,pid,epoch,pointer){const rec=m.selected.get(pid);return rec?.[0]===epoch&&rec?.[1]===pointer?'SELECTED_BIRTH_PROVED':'SELECTED_UNPROVEN';}
const rows=[];
function add(label,value,m){rows.push([label,value,Number(m.armed),m.broker.size,m.selected.size].join('|')+'\n');}
const a=Monitor('global'), b=Monitor('selected'), c=Monitor('dual');
for(const [m,label] of [[a,'current'],[b,'selected_only'],[c,'dual_role']]){
 add(label+'_broker_birth',start(m,101,9,1001,roleBroker),m);
 add(label+'_arm',activate(m,101,9,1001,roleSelected),m);
 add(label+'_selected_birth',start(m,202,10,2002,roleSelected),m);
 add(label+'_selected_probe',check(m,202,10,2002),m);
}
assert.equal(a.armed,true);assert.equal(b.armed,false);assert.equal(c.armed,true);
const d=Monitor('dual');
add('early_selected_ignored',start(d,300,20,3000,roleSelected),d);
add('early_broker_birth',start(d,301,21,3001,roleBroker),d);
add('early_arm',activate(d,301,21,3001,roleSelected),d);
add('early_selected_denied',check(d,300,20,3000),d);
add('later_selected_birth',start(d,302,22,3002,roleSelected),d);
add('later_selected_proved',check(d,302,22,3002),d);
const e=Monitor('dual');
add('unknown_broker',activate(e,10,2,3,roleSelected),e);
start(e,10,2,3,roleBroker);
add('wrong_broker_ptr',activate(e,10,2,4,roleSelected),e);
add('wrong_broker_epoch',activate(e,10,3,3,roleSelected),e);
add('broker_self_selection',activate(e,10,2,3,roleBroker),e);
add('valid_broker',activate(e,10,2,3,roleSelected),e);
for(let i=0;i<1000;i++)add('foreign_churn_'+i,start(e,1000+i,100+i,5000+i,other),e);
assert.equal(e.broker.size,1);assert.equal(e.selected.size,0);
console.log(JSON.stringify({cases:rows.length,sha256:createHash('sha256').update(rows.join('')).digest('hex'),source_pinned:false,native_wfp_executed:false,release_accepted:false}));
