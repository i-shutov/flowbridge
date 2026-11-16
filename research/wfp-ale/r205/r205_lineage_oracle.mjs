#!/usr/bin/env node
// R205 independent stdlib policy oracle (no native PowerShell/WFP execution).
const allowed=new Set(['r203','r204','r205']);
const files=['research/wfp-ale/r204/bfe_engine_contract.py',
 'research/wfp-ale/r204/bfe_engine_oracle.mjs',
 'research/wfp-ale/r204/R204_BFE_ENGINE_CODE_CONSISTENCY.md'];
const commit=(paths,parents=1)=>({paths,parents});
const published=[commit(files),commit(files)];
function legacy(history){
 return history.length===1&&history[0].paths.every(p=>p.startsWith('research/wfp-ale/r203/'));
}
function accepted(history,opts={}){
 if(opts.ancestor===false||opts.pins===false||opts.branch===false)return false;
 for(const c of history){
  if(c.parents!==1||c.paths.length===0)return false;
  for(const path of c.paths){
   const p=path.split('/');
   if(p.length<4||p[0]!=='research'||p[1]!=='wfp-ale'||!allowed.has(p[2])||!p[3])return false;
  }
 }
 return true;
}
const cases=[
 ['anchor',[],{},true],
 ['single R203',[commit(['research/wfp-ale/r203/verify_evidence.py'])],{},true],
 ['published R204 twice',published,{},true],
 ['R205 addition',[...published,commit(['research/wfp-ale/r205/check.js'])],{},true],
 ['changed then reverted kernel source',[...published,commit(['research/wfp-ale/kernel-r19/kernel/src/lib.rs']),commit(['research/wfp-ale/kernel-r19/kernel/src/lib.rs'])],{},false],
 ['untrusted pinned blob',published,{pins:false},false],
 ['wrong branch',published,{branch:false},false],
 ['diverged from anchor',published,{ancestor:false},false],
 ['merge',[...published,commit(['research/wfp-ale/r205/merge'],2)],{},false],
 ['outside allowed paths',[...published,commit(['research/wfp-ale/r206/test.rs'])],{},false],
 ['empty diff',[...published,commit([])],{},false],
];
if(legacy(published))throw Error('R203v4 must reject two-commit R204 HEAD');
for(const [name,history,options,want] of cases){
 const got=accepted(history,options);
 if(got!==want)throw Error('FAIL '+name+' actual='+got+' expected='+want);
 console.log('PASS '+name+' '+(got?'ACCEPT':'REJECT'));
}
console.log(cases.length+'/'+cases.length+' PASS (synthetic graph; no native evidence)');
