// Independent fact-table oracle; only source of authority is the documented
// Microsoft absent-callout contract. No Windows, sockets or WFP calls.
for (const family of ['v4', 'v6'])
for (const selected of [false, true])
for (const tcp of [false, true])
for (const bfe_up of [false, true])
for (const session_alive of [false, true])
for (const registered of [false, true])
for (const kind of ['redirect', 'auth'])
for (const permit_if_missing of [false, true]) {
  const matched = [selected,tcp,bfe_up,session_alive].every(Boolean);
  const result = !matched ? 'NO_R19_MATCH_OR_BFE_UNAVAILABLE'
    : registered ? 'CALLOUT_RUNTIME_UNKNOWN'
    : permit_if_missing ? 'FILTER_TREATED_AS_PERMIT'
    : 'FILTER_TREATED_AS_BLOCK';
  const row={bfe_up, family, kind, permit_if_missing, registered, result,
             selected, session_alive, tcp};
  // Sort keys to match Python sort_keys=True JSONL representation.
  process.stdout.write(JSON.stringify(row)+'\n');
}
