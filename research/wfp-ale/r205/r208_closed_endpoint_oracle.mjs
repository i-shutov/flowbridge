// R208 independent immutable event-trace oracle; PASS demonstrates a source-state gap, not native WFP.
import assert from 'node:assert/strict';
function reduce(events,observeClosure){
 const slots=new Map();let alive=true;const output=[];
 for(const e of events){
  if(e.type==='issue'){
   const ok=!slots.has(e.ep)&&[4,6].includes(e.family||4);
   if(ok)slots.set(e.ep,{family:e.family||4,auth:false,live:true});
   output.push(ok);
  }else if(e.type==='auth'){
   const s=slots.get(e.ep),ok=!!s&&s.live&&!s.auth&&s.family===(e.family||4);
   if(ok)s.auth=true;output.push(ok);
  }else if(e.type==='closure'){
   if(observeClosure&&e.same!==false){const s=slots.get(e.ep);if(s)s.live=false;}
   output.push('close');
  }else if(e.type==='death')alive=false;
  else if(e.type==='claim'){
   const s=slots.get(e.ep),ok=!!s&&s.live&&s.auth&&alive;
   if(s)s.live=false;output.push(ok);
  }else throw Error('unknown event '+e.type);
 }
 return output;
}
const ev=(type,ep,family)=>({type,ep,family});
let n=0;
for(const f of [4,6]){
 const seq=[ev('issue',9,f),ev('auth',9,f),ev('closure',9,f),ev('claim',9,f)];
 assert.deepEqual(reduce(seq,false),[true,true,'close',true]);n++;
 assert.deepEqual(reduce(seq,true),[true,true,'close',false]);n++;
}
const late=[ev('issue',3),ev('closure',3),ev('auth',3),ev('claim',3)];
assert.deepEqual(reduce(late,false),[true,'close',true,true]);n++;
assert.deepEqual(reduce(late,true),[true,'close',false,false]);n++;
const foreign=[ev('issue',4),ev('auth',4),{type:'closure',ep:4,same:false},ev('claim',4)];
assert.equal(reduce(foreign,true).at(-1),true);n++;
const two=[ev('issue',5),ev('issue',6),ev('auth',5),ev('auth',6),ev('closure',5),ev('claim',5),ev('claim',6)];
assert.deepEqual(reduce(two,true).slice(-2),[false,true]);n++;
assert.equal(reduce([ev('issue',7),ev('auth',7),ev('death',7),ev('claim',7)],false).at(-1),false);n++;
assert.deepEqual(reduce([ev('issue',8),ev('claim',8),ev('issue',8) ],false),[true,false,false]);n++;
console.log(`R208 Node compact independent negative traces ${n}/${n} PASS; not native Windows/kernel evidence`);
