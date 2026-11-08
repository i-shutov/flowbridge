// R48 independent Node implementation; no imports from Python, WFP, network, or vendor code.
// Enumerates possible observations; does NOT equate model permit with packet egress.
const perFamily = {};
let cases = 0, modelPermits = 0, unobservedDeathPermits = 0;
let knownExitPermits = 0, epochMismatchPermits = 0, sshLostPermits = 0;
for (const family of [4, 6]) {
  let local = 0;
  for (const death of [false, true])
    for (const notified of [false, true])
      for (const sameEpoch of [false, true])
        for (const healthy of [false, true])
          for (const phase of ['initial_completion', 'reauthorization']) {
            if (notified && !death) continue;
            cases++;
            const granted = !notified && sameEpoch && healthy;
            if (!granted) continue;
            modelPermits++;
            if (death && !notified) { unobservedDeathPermits++; local++; }
            if (notified) knownExitPermits++;
            if (!sameEpoch) epochMismatchPermits++;
            if (!healthy) sshLostPermits++;
          }
  perFamily[String(family)] = local;
}
const api = {
  connectRedirectPendOperationDocumented: false,
  initialAuthPendOperationRequiresCompletionHandle: true,
  reauthorizationAuthPendOperation: 'STATUS_FWP_CANNOT_PEND',
  pendClassifyUnsupportedLayer: 'STATUS_FWP_CANNOT_PEND',
  nullCompleteClassify: 'reauthorize_not_permit'
};
const r = {cases, model_permits: modelPermits, unobserved_death_permits: unobservedDeathPermits,
  known_exit_permits: knownExitPermits, epoch_mismatch_permits: epochMismatchPermits,
  ssh_lost_permits: sshLostPermits, per_family_unobserved: perFamily, api};
if (!(cases === 48 && unobservedDeathPermits > 0 && knownExitPermits === 0 &&
      epochMismatchPermits === 0 && sshLostPermits === 0 &&
      perFamily['4'] === perFamily['6'])) process.exitCode = 1;
console.log(JSON.stringify(r));
