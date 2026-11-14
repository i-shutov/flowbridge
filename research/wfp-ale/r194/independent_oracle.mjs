// Independent R194 Node.js oracle. No imports, no networking, no Windows API.
// Enumerates a separate implementation of the documented conditional scope.
const legs = ['direct_client', 'redirected_client', 'proxy_egress'];
const names = ['family','leg','tcp','original_selected','current_is_broker','records_set','honoring','ticket_valid','route_ready'];
function decision(family, leg, tcp, original, currentBroker, records, honor, ticket, ready) {
  if (original === 0 || tcp === 0) return 'UNMATCHED_OUTSIDE_FILTER';
  if (leg === 'redirected_client' && honor === 0 && ticket === 1 && ready === 1)
    return 'PERMIT_CANDIDATE_NOT_NATIVE_PROOF';
  return 'BLOCK_IF_R19_CALLBACK_RUNS';
}
process.stdout.write(names.join(',')+',r19_model_verdict\n');
for (const family of [4,6]) for (const leg of legs) {
  for (let m = 0; m < 128; m++) {
    // itertools.product repeats=7: first bit changes slowest.
    const v = [6,5,4,3,2,1,0].map(n => (m >> n) & 1);
    process.stdout.write([family, leg, ...v,
      decision(family, leg, ...v)].join(',')+'\n');
  }
}
