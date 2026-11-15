// Independent JS source/lifecycle oracle. No Windows API or network I/O.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const p = readFileSync(resolve(root, 'kernel-r19/policy_windows.rs'), 'utf8');
const r = readFileSync(resolve(root, 'r190/main.rs'), 'utf8');
const compact = s => s.replace(/\s+/g, '');
const policy = compact(p);
const probe = compact(r);
function matches(a,b) { return a.includes(b); }
const observed = (sub, calls, filters, regs) => sub && calls === 4 && filters === 4 && regs === 4
  ? 'STRUCTURE_ONLY_NOT_KERNEL_PROOF' : 'NO_ATTESTATION';
const checks = {
  r19_dynamic_session: matches(policy,'session.flags=FWPM_SESSION_FLAG_DYNAMIC;'),
  r19_sublayer_add: matches(policy,'FwpmSubLayerAdd0('),
  r19_callout_add: matches(policy,'FwpmCalloutAdd0('),
  r19_filter_add: matches(policy,'FwpmFilterAdd0('),
  r190_sublayer_gate: matches(probe,'FwpmSubLayerGetByKey0(') && matches(probe,'"sublayer_get_by_key"'),
  r190_callout_gate: matches(probe,'FwpmCalloutGetByKey0(') && matches(probe,'"callout_get_by_key"'),
  r190_filter_gate: matches(probe,'FwpmFilterGetByKey0(') && matches(probe,'"filter_get_by_key"'),
  r190_registration_gate: matches(probe,'FWPM_CALLOUT_FLAG_REGISTERED'),
  r190_readonly: matches(probe,'FWPM_TXN_READ_ONLY'),
  r190_no_bfe_add: !['FwpmSubLayerAdd0(', 'FwpmCalloutAdd0(', 'FwpmFilterAdd0('].some(x=>probe.includes(x)),
  mutation_dynamic_detected: !policy.replace('session.flags=FWPM_SESSION_FLAG_DYNAMIC','session.flags=0').includes('session.flags=FWPM_SESSION_FLAG_DYNAMIC;'),
  mutation_filter_detected: !probe.replace('FwpmFilterGetByKey0','MUTATED_FILTER_GET').includes('FwpmFilterGetByKey0('),
  clean_no_objects_no_attestation: observed(false,0,0,0) === 'NO_ATTESTATION',
  expired_dynamic_session_no_attestation: observed(false,0,0,0) === 'NO_ATTESTATION',
  unregistered_callout_no_attestation: observed(true,4,4,3) === 'NO_ATTESTATION',
  all_visible_is_only_structure: observed(true,4,4,4) === 'STRUCTURE_ONLY_NOT_KERNEL_PROOF',
};
const total = Object.keys(checks).length;
const passed = Object.values(checks).filter(Boolean).length;
console.log(JSON.stringify({checks,passed,total,scope:'source-level / modeled, not native'}));
if (passed!==total) process.exitCode=1;
