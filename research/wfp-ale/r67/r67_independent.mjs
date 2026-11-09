// R67 standalone no-network independent bitmask oracle; Windows is never invoked.
import {createHash} from 'node:crypto';
const names=['current','original','redirect_seen','auth_seen','ticket','epoch','endpoint','records','health','live','loss','sibling'];
const c={total:0,tcp:0,udp:0,selected_original_foreign_current:0,missed_redirect_selected_original:0,auth_block_requested:0,auth_unobserved:0,auth_outside:0,tcp_model_permit:0,physical_life_gap:0,sibling_direct_possible:0};
const h=createHash('sha256');
for(const family of [4,6])for(const protocol of [6,17])for(let bits=0;bits<4096;bits++){
 const x=names.map((_,i)=>(bits&(1<<i))!==0);
 const [current,original,redSeen,authSeen,ticket,epoch,endpoint,records,health,live,loss,sibling]=x;
 const tcp=protocol===6, red=tcp&&current, auth=tcp&&original;
 let d;
 if(!tcp){c.udp++;d='UDP_OUT_OF_SCOPE';}
 else{
  c.tcp++;
  if(original&&!current){c.selected_original_foreign_current++;c.missed_redirect_selected_original++;}
  if(!auth){c.auth_outside++;d='AUTH_OUT_OF_SCOPE';}
  else if(!authSeen){c.auth_unobserved++;d='AUTH_UNOBSERVED';}
  else if(!(red&&redSeen&&ticket&&epoch&&endpoint&&records&&health&&!loss)){
   c.auth_block_requested++;d='BLOCK_REQUESTED';
  }else{
   c.tcp_model_permit++;d='MODEL_PERMIT_ONLY';
   if(!live)c.physical_life_gap++;
   if(sibling)c.sibling_direct_possible++;
  }
 }
 c.total++;
 h.update(family+'/'+protocol+'/'+bits+':'+d+'\n','utf8');
}
const result={counters:c,sha256:h.digest('hex'),warning:'No status is kernel-owner proof or observed egress; BLOCK_REQUESTED does not prove physical block.'};
console.log(JSON.stringify(result,null,2));
if(c.total!==16384||c.missed_redirect_selected_original!==2048||c.physical_life_gap!==4||result.sha256!=='525e833279b0543c4450eb29e257b3f68d328c06e45d13673c105572cc4796e6')process.exitCode=1;
