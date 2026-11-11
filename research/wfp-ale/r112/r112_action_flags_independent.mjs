// Independent Node implementation; all 32-bit FWP_ACTION_TYPE values include flags.
// User-mode-only model. No network, BFE read or Windows executable.
import {createHash} from 'node:crypto';
const hash=createHash('sha256');
let cases=0,old_visible=0,structural_only=0,old_overclaims=0,bare_action_rejected=0;
const classes={};
for(let rule=0;rule<4;rule++){
  const expectedAction=rule<2?0x5003:0x4005;
  for(const flag of [0,64,32]){
    for(const action of [0x5003,0x4005,3,5,0x1002,0x1001,0x6004,0x5004,0x4003]){
      for(const callout of [0,1,2]){
        for(let app=0;app<13;app++){
          for(let tcp=0;tcp<8;tcp++){
            const old=flag===32?'UNKNOWN_FLAGS':'BASELINE_VISIBLE';
            let newer='STRUCTURAL_ONLY';
            if(flag===32)newer='UNKNOWN_FLAGS';
            else if(action!==expectedAction||callout!==0)newer='UNKNOWN_ACTION_OR_CALLOUT';
            else if(app!==0&&app!==8&&app!==9)newer='UNKNOWN_APP_ID';
            else if(tcp!==0&&tcp!==5)newer='UNKNOWN_TCP';
            hash.update(`${rule}|${flag}|${action}|${callout}|${app}|${tcp}|${old}|${newer}\n`);
            cases++;
            if(old==='BASELINE_VISIBLE')old_visible++;
            if(newer==='STRUCTURAL_ONLY')structural_only++;
            if(old==='BASELINE_VISIBLE'&&newer!=='STRUCTURAL_ONLY')old_overclaims++;
            if((action===3||action===5)&&newer!=='STRUCTURAL_ONLY')bare_action_rejected++;
            classes[newer]=(classes[newer]||0)+1;
          }
        }
      }
    }
  }
}
if(cases!==4*3*9*3*13*8||structural_only!==48)throw Error('matrix drift');
console.log('R112_WFP_ACTION_ORACLE='+JSON.stringify({cases,old_visible,structural_only,
 old_overclaims,bare_action_rejected,classes,sha256:hash.digest('hex'),
 windows_run:false,kernel_proof:false}));
