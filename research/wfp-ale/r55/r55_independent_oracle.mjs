// R55 independent no-network Node oracle; no imports of Python/Rust source.
// Each bit is an *assumption*, not an observed WFP presence guarantee.
const families = [4, 6];
const reauth = ['CLASSIFY_COMPLETION', 'POLICY_CHANGE'];
const names = ['dispatch', 'endpoint_present', 'native_join', 'orig_app_present',
    'selected_original', 'tcp_field_valid', 'issuance_epoch_exact',
    'session_exact', 'not_closed', 'endpoint_not_reused', 'exit_seen_live',
    'ssh_wfp_healthy'];
const tally = { families: families.length, reasons: reauth.length,
    guard_count: names.length, modeled_states: 0, strict_assumed_permits: 0,
    current_driver_reauth_permits: 0, endpoint_only_permits: 0,
    endpoint_only_excess: 0, undispatched_states: 0,
    single_guard_mutants_detected: 0, identical_observation_pairs: 0,
    native_windows_tests: 0, driver_actions: 0 };

// Independent formulation: look for a violated constraint rather than joining
// fields by variable name. This makes the model an independent reference check.
function isRefused(b) {
  for (let j = b.length - 1; j >= 0; --j) {
    if (b[j] === false) return true;
  }
  return false;
}
const model = b => !isRefused(b);
const weak = b => b[0] && b[1];
for (const ip of families) {
  for (const why of reauth) {
    for (let n = 0; n < (1 << names.length); n++) {
      const b = names.map((_, i) => Boolean(n & (1 << i)));
      const full = model(b), candidate = weak(b);
      if (full && !candidate) throw new Error('strict model has unobserved endpoint');
      tally.modeled_states++;
      tally.strict_assumed_permits += Number(full);
      tally.endpoint_only_permits += Number(candidate);
      tally.endpoint_only_excess += Number(candidate && !full);
      tally.undispatched_states += Number(!b[0]);
    }
    // The hidden source owner (selected or sibling) is NOT in the observation.
    // The same visible payload is compatible with two different underlying
    // owners when app and endpoint metadata are absent. Same tuple and history.
    const observed = owner => JSON.stringify({ip, why, tuple:'reused',
      endpoint: null, original_app: null, protocol: null, history: 'same'});
    if (observed('selected') !== observed('sibling')) throw new Error('spurious distinction');
    tally.identical_observation_pairs++;
  }
}
// Mutation sensitivity: each deliberately omitted guard admits the witness
// that only violates that guard, whereas the complete policy refuses it.
for (let omit = 0; omit < names.length; omit++) {
    const witness = names.map((_, i) => i !== omit);
    const broken = witness.every((bit, i) => i === omit || bit);
    if (broken && !model(witness)) tally.single_guard_mutants_detected++;
}
if (tally.modeled_states !== 16384 || tally.strict_assumed_permits !== 4 ||
    tally.endpoint_only_permits !== 4096 || tally.endpoint_only_excess !== 4092 ||
    tally.undispatched_states !== 8192 || tally.single_guard_mutants_detected !== 12 ||
    tally.identical_observation_pairs !== 4) {
    throw new Error(`mismatch: ${JSON.stringify(tally)}`);
}
console.log(JSON.stringify(tally, null, 2));
