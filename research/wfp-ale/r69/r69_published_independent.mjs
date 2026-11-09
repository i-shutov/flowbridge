// Independently written pure Node oracle; no imported models or native calls.
import {createHash} from 'node:crypto';
const bit=(m,i)=>!!(m&(1<<i));
const c={states:0,redirect:Array(7).fill(0),auth:Array(3).fill(0),
  missing_records_nonclean_worlds:0,dead_owner_unknown_issue:0,
  self_continue_without_health:0,no_native_packets:true,
  auth_required_not_in_published_layer_table:['LOCAL_REDIRECT_TARGET_PID','ORIGINAL_DESTINATION']};
const h=createHash('sha256');
for (const family of [4,6]) for (let state=0; state<5; ++state) for(let m=0;m<256;++m){
  const orig=bit(m,0),cur=bit(m,1),tcp=bit(m,2);
  const p=bit(m,3),handle=bit(m,4),ok=bit(m,5),callback=bit(m,6),alive=bit(m,7);
  let r;
  if(!tcp||!cur) r=0;
  else if(p&&!handle) r=1;
  else if(p&&(state===1||state===3)) r=2;
  else if(p&&(state===2||state===4)) r=3;
  else if(!ok) r=4;
  else r=p?5:6;
  let a=(!tcp||!orig)?0:callback?2:1;
  const vals=[r,a,Number(r===6&&(state===1||state===2||state===3)),
    Number(r===6&&!alive),Number(r===2&&!ok)];
  c.states++;c.redirect[r]++;c.auth[a]++;
  c.missing_records_nonclean_worlds+=vals[2];
  c.dead_owner_unknown_issue+=vals[3];
  c.self_continue_without_health+=vals[4];
  h.update(`${family}|${state}|${m}|${vals.join(',')}\n`);
}
c.sha256=h.digest('hex');console.log(JSON.stringify(c,null,2));
