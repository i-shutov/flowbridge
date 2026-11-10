// Independent WFP rights oracle: finite model, not native WFP observations.
import {createHash} from 'node:crypto';
const stages=['redirect_no_right','auth_no_right','kernel_rundown','kernel_stop'];
const actions=['PERMIT','BLOCK','CONTINUE','NONE'];
const sha=createHash('sha256');let total=0;const counts={};
for(const stage of stages){
  for(const ip of [4,6]){
    for(const right of [0,1]){
      for(const prior of actions){
        const invalid=(right===0 && prior!=='PERMIT');
        const outcome=invalid?'CONTRACT_GAP':'DOCUMENTED';
        sha.update(stage+'|'+ip+'|'+right+'|'+prior+'|'+outcome+'\n');
        counts[outcome]=(counts[outcome]||0)+1;total++;
      }
    }
  }
}
console.log(JSON.stringify({total,sha256:sha.digest('hex'),counts:Object.fromEntries(Object.entries(counts).sort())}));
