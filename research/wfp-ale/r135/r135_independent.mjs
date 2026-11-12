// Independent event/action-rights model. No API/network/files/process writes.
import {createHash} from 'node:crypto';
const actions=['BLOCK','PERMIT','CONTINUE','NONE'];
const paths=['redirect_self','redirect_no_write','auth_no_write','callback_stop'];
const lines=[];let invalid=0;
for(const path of paths){
  for(const right of [0,1]){
    if(right===1&&(path==='redirect_no_write'||path==='auth_no_write'))continue;
    for(const incoming of actions){
      const written=(path==='redirect_self'&&right===1)?'CONTINUE':'BLOCK';
      const legal=right===1||(incoming==='PERMIT'&&written==='BLOCK');
      invalid+=Number(!legal);
      lines.push(path+'|'+right+'|'+incoming+'|'+written+'|'+Number(legal)+'\n');
    }
  }
}
const body=lines.join('');
console.log(JSON.stringify({cases:lines.length,contract_invalid:invalid,sha256:createHash('sha256').update(body,'ascii').digest('hex')}));
