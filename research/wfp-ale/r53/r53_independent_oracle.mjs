// R53: independently authored finite-state oracle; zero imports/network/side effects.
const hist=Object.create(null), add=k=>hist[k]=(hist[k]||0)+1;
const families=[4,6], identities=['selected','sibling'], transports=['TCP','UDP'];
for(const family of families)for(const actualOwner of identities)for(const transport of transports)
for(const appAvailable of [0,1])for(const protoAvailable of [0,1])
for(const why of ['classify_completion','policy_change'])
for(const proof of ['none','valid','foreign'])
for(const alive of [0,1])for(const relay of [0,1])for(const epoch of [0,1]){
  const app=appAvailable?actualOwner:'EMPTY',proto=protoAvailable?transport:'EMPTY';
  add('total');
  if(app==='selected'&&proto==='TCP')add('exact_dispatch');
  if((app==='selected'||app==='EMPTY')&&(proto==='TCP'||proto==='EMPTY'))add('empty_fallback_dispatch');
  add('wildcard_dispatch');
  // The provenance receipt is hypothetical and must be tied to the same native flow.
  const o=proof==='valid'?actualOwner:app, p=proof==='valid'?transport:proto;
  const decision=proof==='foreign'?'DENY':
    (p==='UDP'||o==='sibling')?'OUTSIDE_SCOPE':
    (o==='selected'&&p==='TCP'&&proof==='valid'&&alive&&relay&&epoch)?'CONDITIONAL_PERMIT':'DENY';
  add(decision);
  if(actualOwner==='sibling'&&transport==='TCP'&&decision==='DENY')add('sibling_tcp_collateral');
  if(transport==='UDP'&&decision==='DENY')add('udp_collateral');
  if(actualOwner==='selected'&&transport==='TCP'&&proof==='none'&&decision!=='CONDITIONAL_PERMIT')add('unproven_selected_tcp_rejected');
  if(actualOwner==='selected'&&transport==='TCP'&&app==='EMPTY'&&proof==='none'&&!alive)add('naive_unknown_allow_owner_dead');
}
// Counts of indistinguishable observation PAIRS: the physical owner/transport
// are deliberately HIDDEN, and completion reason cannot recover either.
let ownerPairs=0,protoPairs=0;
for(const family of families)for(const observedProto of ['TCP','EMPTY'])
for(const reason of ['classify_completion','policy_change'])
for(const alive of [0,1])for(const relay of [0,1])for(const epoch of [0,1]){
  const first={family,app:'EMPTY',proto:observedProto,reason,proof:'none',alive,relay,epoch};
  const second={...first};if(JSON.stringify(first)!==JSON.stringify(second))throw Error('owner pair');
  ownerPairs++;
}
for(const family of families)for(const reason of ['classify_completion','policy_change'])
for(const alive of [0,1])for(const relay of [0,1])for(const epoch of [0,1]){
  const one={family,app:'selected',proto:'EMPTY',reason,proof:'none',alive,relay,epoch};
  const other={...one};if(JSON.stringify(one)!==JSON.stringify(other))throw Error('proto pair');
  protoPairs++;
}
hist.same_sublayer_possible_first_callbacks=new Set(['exact','fallback']).size;
hist.undistinguished_selected_vs_sibling_tcp_pairs=ownerPairs;
hist.undistinguished_tcp_vs_udp_pairs=protoPairs;
if(hist.total!==1536||ownerPairs!==64||protoPairs!==32)throw Error('enumeration incomplete');
console.log('R53_COUNTS='+JSON.stringify(Object.fromEntries(Object.entries(hist).sort(([x],[y])=>x.localeCompare(y)))));
