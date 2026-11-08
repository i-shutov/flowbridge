// R44 independent *log algebra*, Node standard library only; no network, driver, WFP, FFI.
// Not a translation of the Python VolatileGate state machine.
import assert from 'node:assert/strict';

const historical = (session, family, epoch, tuple) => ({
  session, family, ticket: 99, pid: 1200, epoch, key: epoch + 7000,
  exe: 341, endpoint: 314159, tuple,
});
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// Independent contract: any acknowledged exit MUST remain a permanent
// prohibition of this exact historical ticket, across transient restarts.
function oracle(previousLog, query) {
  const exitOwners = new Set(previousLog.filter(e => e.kind === 'EXIT')
    .map(e => JSON.stringify(e.ticket)));
  return !exitOwners.has(JSON.stringify(query));
}

// Unsafe replay-only receiver model: fresh RAM, old session reused, old frames
// replayed in order, including a prior CLAIM, but missing the acknowledged EXIT.
function replayOnlyReceiver(replayed, session, ticket) {
  const seq = replayed.map(e => e.seq);
  const sequenceValid = seq.length === 2 && seq[0] === 1 && seq[1] === 2;
  return sequenceValid && replayed.every(e => e.session === session) &&
    replayed[0].kind === 'ISSUE' && replayed[1].kind === 'CLAIM' &&
    same(replayed[0].ticket, ticket) && same(replayed[1].ticket, ticket);
}

let worlds = 0, replayCounterexamples = 0, freshSessionBlocks = 0, noReplayBlocks = 0;
for (const family of [4, 6]) for (const epoch of [17, 18])
  for (const tuple of [255, 256]) for (const priorExit of [false, true])
  for (const sessionReused of [false, true]) {
    const t = historical(42, family, epoch, tuple);
    const history = [{kind: 'ISSUE', ticket: t}, {kind: 'CLAIM', ticket: t}];
    if (priorExit) history.push({kind: 'EXIT', ticket: t});
    const currentSession = sessionReused ? 42 : 43;
    const replay = [
      {session: 42, seq: 1, kind: 'ISSUE', ticket: t},
      {session: 42, seq: 2, kind: 'CLAIM', ticket: t},
    ];
    const expected = oracle(history, t);
    const observed = replayOnlyReceiver(replay, currentSession, t);
    if (priorExit && observed && !expected) replayCounterexamples++;
    if (!sessionReused && !observed) freshSessionBlocks++;
    if (!replayOnlyReceiver([], currentSession, t)) noReplayBlocks++;
    assert.equal(observed, sessionReused);
    assert.equal(expected, !priorExit);
    worlds++;
  }
assert.equal(worlds, 32);
assert.equal(replayCounterexamples, 8);
assert.equal(freshSessionBlocks, 16);
assert.equal(noReplayBlocks, 32);
console.log(JSON.stringify({worlds, replayCounterexamples, freshSessionBlocks, noReplayBlocks,
  nativeWindowsExecuted: false, rustExecuted: false, kernelOriginProof: false}, null, 2));
