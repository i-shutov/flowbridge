#!/usr/bin/env node
// Independent R60 no-driver JS crosscheck; no networking, driver, WFP, or Windows APIs.
import {createHash} from 'node:crypto';

const alphabet=['PA','PB','WA','WB','CA','CB','X','N','L','F'];
const needs={PA:[],X:['PA'],PB:['X'],WA:['PA'],WB:['PB'],CA:['WA'],CB:['WB'],N:['X'],L:[],F:[]};
const keys=['weak_permits','strict_permits','weak_after_loss','strict_after_loss',
 'strict_a_after_physical_before_notice','tuple_misbindings','strict_after_notice',
 'apply_calls','completion_calls','strict_permit_despite_tuple_alias'];
function fresh(){return Object.fromEntries(keys.map(k=>[k,0]));}
function calc(trace){
  const score=fresh();
  let lastTuple=null;
  let sshGone=false, wfpGone=false, exited=false, exitNotified=false;
  let readyForComplete={A:false,B:false};
  for(const item of trace){
    switch(item){
      case 'L':sshGone=true;break;
      case 'F':wfpGone=true;break;
      case 'X':exited=true;break;
      case 'N':exitNotified=true;break;
      default:{
        const kind=item[0],slot=item[1];
        if(kind==='P')lastTuple=slot;
        if(kind==='W'){
          score.apply_calls++;
          readyForComplete[slot]=!(sshGone||wfpGone||(slot==='A'&&exitNotified));
        }
        if(kind==='C'){
          score.completion_calls++;
          score.weak_permits++;
          if(sshGone||wfpGone)score.weak_after_loss++;
          if(lastTuple!==slot)score.tuple_misbindings++;
          const keep=readyForComplete[slot]&&!sshGone&&!wfpGone&&!(slot==='A'&&exitNotified);
          if(keep){
            score.strict_permits++;
            if(slot==='A'&&exited&&!exitNotified)score.strict_a_after_physical_before_notice++;
            if(slot==='A'&&exitNotified)score.strict_after_notice++;
            if(sshGone||wfpGone)score.strict_after_loss++;
            if(lastTuple!==slot)score.strict_permit_despite_tuple_alias++;
          }
        }
      }
    }
  }
  return keys.map(k=>score[k]);
}
function enumeration(onTrace){
  const trace=[],done=new Set();
  function walk(){
    if(trace.length===alphabet.length){onTrace(trace);return;}
    for(const action of alphabet){
      if(done.has(action)||!needs[action].every(d=>done.has(d)))continue;
      done.add(action);trace.push(action);walk();trace.pop();done.delete(action);
    }
  }
  walk();
}
const digest=createHash('sha256');
const result={model:'R60 async CONNECT_REDIRECT, NOT native Windows',schedules:0,families:{},totals:fresh()};
for(const ip of [4,6]){
  const stats={schedules:0,...fresh()};
  enumeration(trace=>{
    const outcomes=calc(trace);
    digest.update([ip,trace.join(','),outcomes.join(',')].join('|')+'\n');
    stats.schedules++;
    outcomes.forEach((value,index)=>{stats[keys[index]]+=value;});
  });
  result.families[String(ip)]=stats;
  result.schedules+=stats.schedules;
  keys.forEach(k=>{result.totals[k]+=stats[k];});
}
result.stream_sha256=digest.digest('hex');
console.log(JSON.stringify(result,null,2));
