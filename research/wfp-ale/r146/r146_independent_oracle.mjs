// R146 independent model. No WFP/driver/network calls.
import {createHash} from 'node:crypto';
let rows=0, buf='', cnt=Object.create(null), honorBlocks=0, effectPermits=0;
for(const family of [4,6])for(let n=0;n<512;n++){
 const b=Array.from({length:9},(_,k)=>Number((n&(1<<(8-k)))!==0));
 const [sel,honor,redir,reauth,meta,local,receipt,write,prior]=b;
 const admit=redir===1&&honor===0&&reauth===0&&meta===1&&local===1&&receipt===1;
 const result=sel===0?'NOT_SELECTED':admit&&write===1?'PERMIT_CANDIDATE':
    write===1||prior===1?'BLOCK_CANDIDATE':'PRESERVE_UNPROVEN';
 if(sel&&honor&&write){if(result!=='BLOCK_CANDIDATE')throw Error('honoring');honorBlocks++;}
 if(sel&&honor&&result==='PERMIT_CANDIDATE')throw Error('honoring_permit');
 if(sel&&!honor&&redir&&!reauth&&meta&&local&&receipt&&write){
   if(result!=='PERMIT_CANDIDATE')throw Error('effective');effectPermits++;
 }
 cnt[result]=(cnt[result]||0)+1;
 buf+=family+'|'+b.join('')+'|'+result+'\n';rows++;
}
if(rows!==1024||honorBlocks!==128||effectPermits!==4)throw Error('counts');
const counts=Object.fromEntries(Object.keys(cnt).sort().map(k=>[k,cnt[k]]));
process.stdout.write(JSON.stringify({
 counts,favorable_effective_permit_candidates:effectPermits,honoring_stage_seen_in_windows:false,
 honoring_write_block_candidates:honorBlocks,kernel_driver_executed:false,release_go:false,rows,
 sha256:createHash('sha256').update(buf).digest('hex'),source_model:'PINNED_R19_ONLY',
 subsequent_authorization_proved:false
})+'\n');
