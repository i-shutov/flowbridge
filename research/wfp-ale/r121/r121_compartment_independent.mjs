// R121 independent Node oracle: bytewise destination labels, not imported Python model.
// No WFP, socket, network, process or driver API.
import {createHash} from 'node:crypto';
const addresses = [[4,'10.55.0.7'],[4,'198.51.100.17'],
                   [6,'fd00:dead::7'],[6,'2001:db8::17']];
const ports=[443,8443], compartments=[1,7,42,99];
const epochs=[100,101], endpoints=[11,12];
const lines=[], groups=new Map();
let candidates=0, strict=0;
for(const [family,addr] of addresses) for(const port of ports)
for(const compartment of compartments) for(const epoch of epochs)
for(const endpoint of endpoints) for(const ssh of [0,1]) for(const protocol of [6,17]) {
  const eligible = Number(protocol===6 && ssh===1);
  const scoped = Number(eligible===1 && compartment===7);
  const target=[family,addr,port].join('/');
  lines.push([family,addr,port,compartment,epoch,endpoint,ssh,protocol,eligible,scoped].join('|'));
  candidates+=eligible; strict+=scoped;
  if(eligible) {
    const values=groups.get(target)||[];
    values.push({compartment,epoch,endpoint});groups.set(target,values);
  }
}
let pairs=0,sameOwner=0;
for(const values of groups.values()) {
  for(let i=0;i<values.length;i++) for(let j=i+1;j<values.length;j++) {
    if(values[i].compartment===values[j].compartment)continue;
    pairs++;
    if(values[i].epoch===values[j].epoch && values[i].endpoint===values[j].endpoint)sameOwner++;
  }
}
const stats={cases:lines.length,tcp_ssh_candidates:candidates,
  explicit_compartment_7_candidates:strict,
  compartment_unqualified_candidates:candidates-strict,
  cross_compartment_same_remote_selector_pairs:pairs,
  same_epoch_endpoint_cross_compartment_pairs:sameOwner,
  matrix_sha256:createHash('sha256').update(lines.join('\n')+'\n').digest('hex'),
  native_wfp_observed:false,kernel_origin_proven:false,no_direct_proven:false};
if(lines.length!==512 || candidates!==128 || strict!==32 || pairs!==768 || sameOwner!==192)
  throw Error('R121 independent oracle counter mismatch');
console.log('R121_MATRIX '+JSON.stringify(stats));
