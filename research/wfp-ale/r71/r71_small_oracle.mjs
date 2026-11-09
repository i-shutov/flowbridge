// R71 small deterministic counterexample; no Windows APIs, network or driver.
const states=['ABSENT','NULL_UNKNOWN','NULL_HYPOTHETICAL_NOT','NOT','SELF','OTHER','PREVIOUS_SELF','FUTURE_UNKNOWN'];
const old=['UNQUERIED_ISSUE','UNVERIFIED','HYPOTHETICAL_ISSUE','QUERIED_ISSUE','NO_NEW','BLOCK_REQUESTED','NO_NEW','BLOCK_REQUESTED'];
const strict=states.map((_,i)=>i===3?'CONDITIONAL':i===4||i===6?'NO_NEW':'BLOCK_REQUESTED');
if(old.length!==8||strict.filter(x=>x==='CONDITIONAL').length!==1) throw Error('invalid states');
let total=0,unqueried=0,conditional=0,originalMismatch=0,siblingUnexcluded=0;
for(let v6=0;v6<2;v6++) for(let current=0;current<2;current++)
for(let original=0;original<2;original++) for(let tcp=0;tcp<2;tcp++)
for(let lease=0;lease<2;lease++) for(let ssh=0;ssh<2;ssh++)
for(let wfp=0;wfp<2;wfp++) for(let sibling=0;sibling<2;sibling++)
for(let state=0;state<8;state++){
 total++;if(!current||!tcp||!lease)continue;
 if(state===0)unqueried++;
 if(state===3){conditional++;if(!original)originalMismatch++;if(sibling)siblingUnexcluded++;}
}
if(total!==2048||unqueried!==32||conditional!==32||originalMismatch!==16||siblingUnexcluded!==16)throw Error('counterexample regression');
process.stdout.write(JSON.stringify({model_only:true,total,unqueried,conditional,originalMismatch,siblingUnexcluded,states,old,strict})+'\n');
