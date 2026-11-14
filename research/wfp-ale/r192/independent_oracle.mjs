// R192 independent, read-only negative oracle. No Windows API or sockets.
// Uses a decision table rather than importing Python logic.
const yes = [0,1];
const header = 'family,policy_live,selected,configured,route_matches,writable,armed,process_live,ssh_alive,outcome\n';
const cases = [];
function outcome(policy, selected, configured, same, writable, armed) {
  // Ordered rules are independent from source-language test implementation.
  if (policy === 0) return 'NO_FILTER_UNKNOWN';
  if (selected === 0) return 'OUT_OF_SCOPE';
  if (configured === 0) return 'BLOCK_BEFORE_APPID';
  if (writable === 0) return 'PRIOR_ACTION_UNKNOWN';
  if (same === 0) return 'CONTINUE_NO_READY_CHECK';
  return armed === 0 ? 'BLOCK_AFTER_READY_CHECK' : 'REQUIRES_NATIVE_PROOF';
}
for (const family of ['v4','v6'])
for (const policy of yes)
for (const selected of yes)
for (const configured of yes)
for (const same of yes)
for (const writable of yes)
for (const armed of yes)
for (const processLive of yes)
for (const sshAlive of yes) {
  cases.push([family,policy,selected,configured,same,writable,armed,processLive,sshAlive,
              outcome(policy, selected, configured, same, writable, armed)].join(','));
}
if (cases.length !== 512 || cases.filter(x => x.endsWith('CONTINUE_NO_READY_CHECK')).length !== 16)
  throw Error('R192 oracle expectations failed');
process.stdout.write(header + cases.join('\n') + '\n');
