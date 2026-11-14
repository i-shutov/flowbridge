// R184 independent declarative oracle. User mode, pure JS; no socket or WFP API.
const scenarios = ['owner_exit','close_then_replace','fixed_key_overlap','distinct_key_overlap'];
const timelines = {
  owner_exit: [['baseline',1],['owner_exit',0]],
  close_then_replace: [['baseline',1],['close_old',0],['commit_new',1]],
  fixed_key_overlap: [['baseline',1],['stage_new_fixed',1],['close_old',0],['retry_new',1]],
  distinct_key_overlap: [['baseline',1],['stage_unique',2],['close_old',1]],
};
function canon(o) { return JSON.stringify(Object.fromEntries(Object.entries(o).sort(([a],[b])=>a.localeCompare(b,'en')))); }
let n=0, gaps=0, collisions=0;
for (const family of ['v4','v6']) for(const protocol of ['tcp','udp'])
for(const origin of ['selected','sibling']) for(const external_blocker of [false,true])
for(const scenario of scenarios) {
  const ruleMatch=origin==='selected' && protocol==='tcp';
  const trace=timelines[scenario];
  const coverage=trace.map(([,count])=>Number(ruleMatch && count>0));
  const owned_gap=ruleMatch && coverage.includes(0);
  const collision=scenario==='fixed_key_overlap';
  const timeline=trace.map(([label],i)=>label+':'+coverage[i]).join('>');
  const obj={family,protocol,origin,external_blocker,scenario,timeline,owned_gap,
    collision,effective_result:'UNKNOWN',alternative_guard_may_block:external_blocker};
  console.log(canon(obj));
  n++; gaps+=Number(owned_gap);collisions+=Number(collision);
}
if(n!==64 || gaps!==12 || collisions!==16) throw Error('oracle count mismatch');
