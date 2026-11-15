// R197 independent transaction-state oracle; run node .../r197_independent.mjs [r190/main.rs]
import { readFileSync } from 'node:fs';
function oracle(events) {
  let inTxn = false;
  for (const e of events) {
    if (e === 'begin') { if (inTxn) return 'FWP_E_TXN_IN_PROGRESS'; inTxn = true; }
    else if (e === 'session_create' && inTxn) return 'FWP_E_TXN_IN_PROGRESS';
    else if (e === 'commit' || e === 'abort') inTxn = false;
  }
  return 'SUCCESS_BY_TRANSACTION_RULE_ONLY';
}
const cases = [
  [['begin','session_create','filter_create','commit'],'FWP_E_TXN_IN_PROGRESS'],
  [['session_create','begin','filter_create','commit'],'SUCCESS_BY_TRANSACTION_RULE_ONLY'],
  [['begin','filter_create','session_create'],'FWP_E_TXN_IN_PROGRESS'],
  [['begin','filter_create','commit','session_create'],'SUCCESS_BY_TRANSACTION_RULE_ONLY'],
  [['begin','begin'],'FWP_E_TXN_IN_PROGRESS'],
  [['begin','abort','session_create'],'SUCCESS_BY_TRANSACTION_RULE_ONLY'],
  [['session_create','session_create','begin','commit'],'SUCCESS_BY_TRANSACTION_RULE_ONLY'],
  [['begin','session_create'],'FWP_E_TXN_IN_PROGRESS'],
];
for (const [seq, expected] of cases) {
  if (oracle(seq) !== expected) throw Error('R197 oracle mismatch at '+seq.join(','));
}
if (process.argv[2]) {
  const s = readFileSync(process.argv[2], 'utf8');
  const r = s.match(/    fn run\(selected_exe:[\s\S]*?(?=    pub fn main\()/)?.[0];
  const i = s.match(/    unsafe fn inspect\([\s\S]*?(?=    fn run\()/)?.[0];
  if (!r || !i) throw Error('source functions absent');
  const positions = ['session_count(engine.0)','FwpmTransactionBegin0(engine.0','inspect(engine.0, &selected, sessions)'].map(k=>r.indexOf(k));
  if (positions.some(k=>k<0) || !(positions[0]<positions[1] && positions[1]<positions[2]))
    throw Error('unsafe order of BFE session enumeration');
  if (i.includes('session_count(engine)?')) throw Error('session enumeration under transaction');
  if (!s.includes('FwpmFilterCreateEnumHandle0(')) throw Error('lost transactional filter snapshot');
  if (/Fwpm(?:Filter|Callout|SubLayer)Add0\s*\(/.test(s)) throw Error('policy mutation API');
}
console.log('R197 independent oracle 8/8 PASS'+(process.argv[2]?', full-source guard PASS':''));
