// Independent offline Node oracle. No network or Windows system calls.
import {createHash} from 'node:crypto';
const dest=[[4,'10.55.0.7'],[6,'fd00:dead::7']];
const ports=[443,8443], compartments=[1,7,42], epochs=[100,101];
const lines=[], buckets=new Map();
let candidates=0, gated=0;
for(const [f,ip] of dest)for(const port of ports)
for(const compartment of compartments)for(const epoch of epochs)
for(const healthy of [0,1])for(const protocol of [6,17]){
  const accepted=Number(Boolean(healthy)&&protocol===6);
  const narrow=Number(accepted===1&&compartment===7);
  candidates+=accepted;gated+=narrow;
  lines.push([f,ip,port,compartment,epoch,healthy,protocol,accepted,narrow].join('|'));
  if(accepted){
    const selector=`UNKNOWN_BROKER_ROUTE|${f}|${ip}|${port}`;
    const group=buckets.get(selector)||[]; group.push([compartment,epoch]);buckets.set(selector,group);
  }
}
let pairs=0, sameEpoch=0;
for(const group of buckets.values())for(let i=0;i<group.length;i++)for(let j=i+1;j<group.length;j++){
  if(group[i][0]!==group[j][0]) {pairs++;if(group[i][1]===group[j][1])sameEpoch++;}
}
const result={cases:lines.length,source_projection_candidates:candidates,
  explicit_scope_candidates:gated,cross_compartment_indistinguishable_pairs:pairs,
  same_epoch_indistinguishable_pairs:sameEpoch,
  matrix_sha256:createHash('sha256').update(lines.join('\n')+'\n').digest('hex'),
  windows_egress_routing_verified:false,wfp_kernel_causality_verified:false,
  global_no_direct_verified:false};
if(lines.length!==96||candidates!==24||gated!==8||pairs!==48||sameEpoch!==24)throw Error('oracle invariant failure');
console.log('R122_MATRIX '+JSON.stringify(result));
