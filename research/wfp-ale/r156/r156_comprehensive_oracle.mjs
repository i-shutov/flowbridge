// Independent decision-table oracle: no Python imports, no OS/WFP interaction.
import {createHash} from 'node:crypto';
const stages=['NO_OUTPUT','RUNDOWN_DENIED','STOPPING','UNCONFIGURED','NULL_INPUT','WRONG_LAYER','INVALID_APPID','FOREIGN_APPID','MISSING_IDENTITY','NON_TCP','SELF','PREVIOUS_SELF','OTHER','NOT_REDIRECTED','RECORDS_ABSENT'];
const actions=['BLOCK','PERMIT','CONTINUE','NONE'];
const earlyBlocks=new Set(['RUNDOWN_DENIED','STOPPING','UNCONFIGURED','NULL_INPUT','INVALID_APPID']);
const hash=createHash('sha256'),counts={};let n=0,selves=0;
for(const family of [4,6])for(const prior of actions)for(const rights of [0,1,256,257,4294967294,4294967295])for(const stage of stages){
 const writable=rights%2===1;
 let action=stage==='NO_OUTPUT'?prior:writable?'CONTINUE':prior;
 let next=rights,path,query=false,final=true,deny;
 if(stage==='NO_OUTPUT'){path=stage;final=false;}
 else if(earlyBlocks.has(stage)){deny=stage;}
 else if(stage==='WRONG_LAYER'||stage==='FOREIGN_APPID'){path=stage+'_RETURN';}
 else if(!writable){deny='NO_WRITE_BEFORE_QUERY';}
 else if(stage==='MISSING_IDENTITY'||stage==='NON_TCP'){deny=stage;}
 else {
  query=stage!=='RECORDS_ABSENT';
  if(stage==='SELF'||stage==='PREVIOUS_SELF'){path=stage+':RETURN_CONTINUE';selves++;}
  else if(stage==='OTHER'){deny='OTHER_REDIRECT';}
  else{path='MODIFYING_PATH_NOT_MODELLED';final=false;}
 }
 if(deny){
  const block=writable||action==='PERMIT';
  path=deny+(block?':BLOCK':':PRESERVE');
  if(block){action='BLOCK';next=rights-(writable?1:0);}
 }
 counts[path]=(counts[path]||0)+1;n++;
 hash.update([family,prior,rights,stage,path,action,next,Number(query),Number(final)].join('|')+'\n');
}
if(n!==720||selves!==48)throw Error('incomplete campaign');
console.log(JSON.stringify({states:n,reachable_self_returns:selves,categories:Object.fromEntries(Object.entries(counts).sort()),sha256:hash.digest('hex'),native_wfp_executed:false,release_accepted:false}));
