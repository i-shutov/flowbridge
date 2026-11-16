#!/usr/bin/env node
// Independent JS oracle for R199 BFE engine-code/exit integrity; no kernel proof.
import fs from 'node:fs';
import path from 'node:path';
function accepts(bfe, exit) {
  if (!Number.isInteger(exit) || (exit!==0 && exit!==3) || bfe===null ||
      typeof bfe!=='object' || Array.isArray(bfe) || bfe.kernel_proof!==false ||
      bfe.atomic!==false) return false;
  if (!Number.isInteger(bfe.engine_api_code) || bfe.engine_api_code<0 ||
      bfe.engine_api_code>0xffffffff) return false;
  if (bfe.state==='MANAGEMENT_READBACK_NOT_PROOF')
    return bfe.engine_api_code===0 && exit===0;
  if (bfe.state==='UNKNOWN') return exit===3;
  return false;
}
function selfTest() {
 const cases=[
  ['MANAGEMENT_READBACK_NOT_PROOF',0,0,true],['UNKNOWN',5,3,true],['UNKNOWN',0,3,true],
  ['MANAGEMENT_READBACK_NOT_PROOF',5,0,false],['MANAGEMENT_READBACK_NOT_PROOF',undefined,0,false],
  ['MANAGEMENT_READBACK_NOT_PROOF',0,3,false],['UNKNOWN',5,0,false],['UNKNOWN',-1,3,false],
  ['UNKNOWN',0x100000000,3,false],['UNKNOWN',true,3,false]
 ];
 for(const [state,code,exit,want] of cases){
  const b={state,kernel_proof:false,atomic:false};
  if(code!==undefined)b.engine_api_code=code;
  if(accepts(b,exit)!==want)throw Error('oracle mismatch: '+state+'/'+code+'/'+exit);
 }
 console.log('R204-JS 10/10 PASS: semantic gate only, not Windows runtime');
}
try {
 if(process.argv.length===3 && process.argv[2]==='--self-test') selfTest();
 else if(process.argv.length===4 && process.argv[2]==='--evidence-dir'){
  const dir=process.argv[3], e=JSON.parse(fs.readFileSync(path.join(dir,'evidence.json'),'utf8').replace(/^\uFEFF/,''));
  if(e.bfe_requested!==true){console.log('NOT_APPLICABLE_BFE_NOT_REQUESTED');process.exitCode=3;}
  else{
   const item=e.results['r199-readback'];
   if(item.stdout!=='r199-readback.stdout.txt')throw Error('unexpected BFE stdout path');
   const bfe=JSON.parse(fs.readFileSync(path.join(dir,item.stdout),'utf8').replace(/^\uFEFF/,''));
   const ok=accepts(bfe,item.exit_code);
   console.log(ok?'R204_BFE_MANAGEMENT_CONSISTENCY_ACCEPTED_NOT_KERNEL_PROOF':'REJECTED_NO_GO');
   if(!ok)process.exitCode=1;
  }
 } else throw Error('usage: --self-test | --evidence-dir DIR');
} catch(e) { console.error('REJECTED_NO_GO: '+String(e)); process.exitCode=1; }
