// R200 source-bound cross-module contract oracle; standalone Node, read-only.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
const dir = dirname(fileURLToPath(import.meta.url));
const root = join(dir, '..', 'kernel-r19', 'kernel', 'src');
const ledger = readFileSync(join(root, 'ledger.rs'), 'utf8');
const runtime = readFileSync(join(root, 'lib.rs'), 'utf8');
const redirect = readFileSync(join(root, 'redirect.rs'), 'utf8');
let passed = 0;
function check(ok, msg) { if (!ok) throw Error(`source contract changed: ${msg}`); passed++; }
check(/MAX_OWNERS:\s*usize\s*=\s*256\s*;/.test(ledger), 'bounded owner table');
check(/if self\.used\s*==\s*MAX_OWNERS\s*\{\s*self\.lost\s*=\s*true;\s*return Err\(Denied::Full\)/.test(ledger), 'full poisons ledger');
check(/self\.owners\[self\.used\]\s*=\s*owner;\s*self\.used\s*\+=\s*1;/.test(ledger), 'non-evicting append');
const died = ledger.match(/pub fn died\([\s\S]*?\n    }/g)?.[0] ?? '';
check(died.includes('owner.live=false') && !/used\s*[-=]/.test(died), 'exit does not free capacity');
check(/pub fn lookup\(&self,pid:u64\)[\s\S]*?if self\.lost\s*\{return None;\}/.test(ledger), 'global loss rejects lookup');
const proc = runtime.match(/unsafe extern "C" fn process_event\([\s\S]*?\n}/)?.[0] ?? '';
check(proc.includes('(*STATE.0.get()).born(owner)') && !proc.includes('ROUTE'), 'all valid creates enter owner table, no selected filter');
check(/PsSetCreateProcessNotifyRoutineEx\(Some\(process_event\),0\)/.test(runtime), 'process-wide notify registered');
check(/let owner=\(\*STATE\.0\.get\(\)\)\.lookup\(r\.pid\)/.test(redirect) && /if !r\.armed\|\|r\.book\.lost/.test(redirect), 'lookup failure disables ready');
console.log(`R200 source-bound contracts: ${passed}/${passed} PASS; source-only, no kernel execution`);
