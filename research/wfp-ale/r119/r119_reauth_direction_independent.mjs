/* Independently implemented, table-based oracle. No Windows APIs, sockets,
   WFP, files, drivers or OS state. Always NON-PROOF. */
import {createHash} from 'node:crypto';
const ORIGINS=['OUT_CONNECT','IN_RECV_ACCEPT'];
const DIRECTIONS=['OUT','IN'];
const REASONS=['POLICY','INTERFACE','PENDING'];
const FAMILIES=[4,6];
const EPOCHS=['SAME','REUSED_PID'];
const TICKETS=['SAME','REUSED_TUPLE_NEW_TICKET'];
const WFP=['PRESENT','LOST'];
const SSH=['UP','DOWN'];
const TRANSPORTS=['TCP','UDP'];
const table={OUT_CONNECT:'AUTH_CONNECT',IN_RECV_ACCEPT:'AUTH_RECV_ACCEPT'};
const wrong={OUT:'AUTH_CONNECT',IN:'AUTH_RECV_ACCEPT'};
let mistakes=0, total=0, hash=createHash('sha256');
let seen = new Map(), witnesses=[
 ['OUT_CONNECT','IN','POLICY',4,'AUTH_CONNECT_V4','AUTH_RECV_ACCEPT_V4'],
 ['IN_RECV_ACCEPT','OUT','INTERFACE',6,'AUTH_RECV_ACCEPT_V6','AUTH_CONNECT_V6']
];
for(const o of ORIGINS)for(const d of DIRECTIONS)for(const r of REASONS)
for(const f of FAMILIES)for(const e of EPOCHS)for(const t of TICKETS)
for(const w of WFP)for(const s of SSH)for(const p of TRANSPORTS){
  const actual=`${table[o]}_V${f}`, guessed=`${wrong[d]}_V${f}`;
  const mis=Number(actual!==guessed);
  const weak=(o==='OUT_CONNECT'&&e==='SAME'&&t==='SAME'&&w==='PRESENT'&&s==='UP'&&p==='TCP');
  const status=weak?'CORROBORATION_NOT_PROOF':'UNKNOWN_OR_OUT_OF_SCOPE';
  hash.update([o,d,r,f,e,t,w,s,p,actual,guessed,mis,status].join(',')+'\n');
  mistakes+=mis;total++;
  const obs=[d,r,f,e,t,w,s,p].join('|');
  if(!seen.has(obs))seen.set(obs,new Set());
  seen.get(obs).add(actual);
}
if(total!==768||mistakes!==384||seen.size!==384)throw Error('unexpected cardinality');
for(const layers of seen.values())if(layers.size!==2)throw Error('ambiguous evidence accidentally treated as unique');
if(table.OUT_CONNECT===wrong.IN || table.IN_RECV_ACCEPT===wrong.OUT)throw Error('negative witness lost');
console.log(JSON.stringify({scenarios:total,direction_only_misclassifications:mistakes,
  same_observation_opposite_origin_pairs:seen.size,sha256:hash.digest('hex'),
  counterexamples:witnesses,kernel_origin_proof:false,system_no_direct_proof:false,
  real_wfp_calls:0,installed_driver:false}));
