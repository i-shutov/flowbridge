// Independent R186 oracle. No Windows calls or dependencies.
function* combinations(prefix, min) {
  if (prefix.length === 8) { yield prefix; return; }
  for (let n = min; n <= 2; n++) yield* combinations(prefix + n, n);
}
function isPresent(mode, phase) { return mode === 'stable' || phase !== 1; }
function epoch(mode, phase) { return mode === 'stable' || phase === 0 ? 'A' : 'B'; }
function row(mode, seq, hidden, txn) {
  const phases = Array.from(seq, Number);
  const readings = phases.map((p, i) => {
    const phase = txn ? phases[0] : p;
    if (!isPresent(mode, phase)) return null;
    return {e: epoch(mode, phase), reg: !(mode === 'unregistered' && phase === 2 && i >= 4)};
  });
  const complete = readings.every(v => v !== null);
  const registered = readings.every((v, i) => v !== null && (i < 4 || v.reg));
  const seen = [...new Set(readings.filter(Boolean).map(v => v.e))].sort().join('');
  const green = complete && registered;
  return {
    mode, sequence: seq, hidden_foreign: hidden, transaction: txn,
    naive_green: green, read_ok: complete, registered,
    mixed_epochs: seen.length === 2, observed_epochs: seen,
    status: txn && green ? 'OWN_OBJECTS_SNAPSHOT_ONLY' : 'NON_ATOMIC_OR_INCOMPLETE',
    enforcement_proven: false, continuous_coverage_proven: false
  };
}
const ordered = x => Object.fromEntries(Object.entries(x).sort(([a],[b]) => a.localeCompare(b, 'en')));
for (const mode of ['churn', 'stable', 'unregistered']) {
  for (const seq of combinations('', 0)) {
    for (const hidden of [false, true]) {
      for (const txn of [false, true]) {
        process.stdout.write(JSON.stringify(ordered(row(mode, seq, hidden, txn))) + '\n');
      }
    }
  }
}
