// Independent bitwise oracle. No Windows API, network, WFP or process operations.
import {createHash} from 'node:crypto';
const rows=[];let missed=0,completeCount=0,readyCount=0;
for(const family of [4,6]){
 for(let state=0;state<64;state++){
  // Explicitly decode last two bits as heartbeat and notification; high 4 as filter mask.
  const mask=state>>>2, ping=(state>>>1)&1, notified=state&1;
  const ownedComplete=Number((mask&15)===15);
  const brokerReady=Number(ping===1);
  const blind=Number(brokerReady===1 && ownedComplete===0 && notified===0);
  missed+=blind;completeCount+=ownedComplete;readyCount+=brokerReady;
  rows.push([family,mask.toString(2).padStart(4,'0'),ping,notified,
    ownedComplete,brokerReady,blind].join('|'));
 }
}
if(rows.length!==128||missed!==30||completeCount!==8||readyCount!==64)throw Error('counts');
for(const family of [4,6]){
 if(!rows.includes(`${family}|1111|1|0|1|1|0`)||
    !rows.includes(`${family}|0000|1|0|0|1|1`))throw Error('observation-pair');
}
if(rows.some(s=>s.includes('DIRECT_OBSERVED')||s.includes('PACKET_PASS')))throw Error('overclaim');
console.log('R107 NODE PASS states=128 missed_model=30 complete=8 ready=64');
console.log('SHA256='+createHash('sha256').update(rows.join('\n')+'\n').digest('hex'));
