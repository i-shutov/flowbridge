// Independent Node oracle: only synthetic policy lifetime, never packet admission.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
const F=[4,6], S=['ALIVE','CLOSED','RPC_RUNDOWN','PROCESS_EXIT'], I=['NONE','COMMITTED'],B=['LIVE','DEAD'],H=['UP','DOWN'],O=['ALLOW_UNKNOWN','BLOCK_UNKNOWN'],C=['RUNNING','TERMINATED'];
const entries=[]; let violations=0, noOwn=0, own=0;
for(const family of F)for(const session of S)for(const install of I)for(const broker of B)for(const ssh of H)for(const other_policy of O)for(const client of C){
  const inputs={family,session,install,broker,ssh,other_policy,client};
  const own_rules=(session==='ALIVE' && install==='COMMITTED');
  let flowbridge_status;
  if (own_rules && broker==='LIVE' && ssh==='UP')flowbridge_status='RULES_PRESENT_NOT_KERNEL_PROOF';
  else if(own_rules) flowbridge_status='RULES_PRESENT_BUT_DELIVERY_UNPROVEN';
  else flowbridge_status='NOT_GUARDED_BY_FLOWBRIDGE';
  const output={family,own_rules,flowbridge_status,other_policy,client,direct_packet_observed:false,leak_proven:false,packetbound_g2_pass:false};
  if(session!=='ALIVE' && own_rules) violations++;
  if(own_rules)own++;else noOwn++;
  entries.push(JSON.stringify({inputs,output},Object.keys({inputs:null,output:null}))); // compare via canonical below
}
const expected=F.length*S.length*I.length*B.length*H.length*O.length*C.length;
if(entries.length!==expected || violations)throw new Error('oracle invariant failed');
const canonical = (x)=>JSON.stringify(x,Object.keys(x).sort());
// Run independent truth-table checks against Python output read from its matrix fixture.
const records=readFileSync(process.argv[2],'utf8').trim().split('\n').map(x=>JSON.parse(x));
if(records.length!==expected)throw new Error('matrix count mismatch');
let checked=0;
for(const r of records){
 const v=r.inputs, o=r.output;
 const owned=v.session==='ALIVE'&&v.install==='COMMITTED';
 const expectedStatus=!owned?'NOT_GUARDED_BY_FLOWBRIDGE':v.broker==='LIVE'&&v.ssh==='UP'?'RULES_PRESENT_NOT_KERNEL_PROOF':'RULES_PRESENT_BUT_DELIVERY_UNPROVEN';
 if(owned!==o.own_rules || o.flowbridge_status!==expectedStatus || o.direct_packet_observed!==false || o.leak_proven!==false || o.packetbound_g2_pass!==false)throw Error(`mismatch ${checked}`);
 checked++;
}
console.log(JSON.stringify({cases:checked,own,noOwn,violations,oracle:'independent direct predicate',native_execution:'NOT_RUN'}));
