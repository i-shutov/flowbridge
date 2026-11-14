// Independent JS static read-only gate (not Rust compiler / WFP proof).
import {readFileSync} from 'node:fs';
const src = readFileSync(new URL('./src/main.rs', import.meta.url), 'utf8');
const allowed = new Set([
 'FwpmEngineOpen0','FwpmEngineClose0','FwpmFreeMemory0',
 'FwpmTransactionBegin0','FwpmTransactionCommit0','FwpmTransactionAbort0',
 'FwpmSessionCreateEnumHandle0','FwpmSessionEnum0','FwpmSessionDestroyEnumHandle0',
 'FwpmSubLayerGetByKey0','FwpmFilterGetByKey0','FwpmCalloutGetByKey0'
]);
function audit(s) {
 const calls = [...new Set([...s.matchAll(/\b(Fwpm\w+|Fwps\w+|DeviceIoControl|WSAIoctl|CreateService|socket|connect|bind|listen|send|recv)\s*\(/g)].map(x=>x[1]))].sort();
 const violations=calls.filter(x=>!allowed.has(x));
 const missing=[...allowed].filter(x=>x!=='FwpmTransactionAbort0'&&!calls.includes(x)).sort();
 const guards={
  read_only_transaction:/FwpmTransactionBegin0\s*\(\s*engine\.0\s*,\s*FWPM_TXN_READ_ONLY\s*\)/.test(s),
  no_dynamic_session:!s.includes('FWPM_SESSION_FLAG_DYNAMIC'),
  no_kernel_claim:s.includes('kernel_identity\\\":\\\"UNKNOWN')||s.replaceAll('\\\\','\\').includes('kernel_identity\\\":\\\"UNKNOWN'),
  no_enforcement_claim:s.includes('enforcement\\\":\\\"UNKNOWN')||s.replaceAll('\\\\','\\').includes('enforcement\\\":\\\"UNKNOWN'),
  no_continuity_claim:s.includes('continuity\\\":\\\"UNKNOWN')||s.replaceAll('\\\\','\\').includes('continuity\\\":\\\"UNKNOWN'),
  no_go_token:!/(\bPACKETBOUND_PASS\b|\bLEAK_FREE\b|\bG2_PASS\b)/.test(s)
 };
 return {safe:violations.length===0&&missing.length===0&&Object.values(guards).every(Boolean),calls,violations,missing,guards};
}
console.log(JSON.stringify(audit(src)));
