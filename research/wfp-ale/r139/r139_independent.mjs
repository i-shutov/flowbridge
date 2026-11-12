// Independently implemented bit-level oracle; no import of Python or Rust source.
import { createHash } from 'node:crypto';
const stages = [
  'NO_TRUSTED_ACCEPT', 'RECORD_QUERY_FAILED', 'CONTEXT_QUERY_FAILED',
  'CONTEXT_INVALID', 'CLAIM_REJECTED', 'UPSTREAM_SOCKET_FAILED',
  'SET_RECORDS_FAILED', 'CONNECT_FAILED', 'SSH_AUTH_FAILED',
  'CHANNEL_FAILED', 'REVOKED', 'CONDITIONAL_RELAY',
];
const lines = [], counts = Object.fromEntries(stages.map(stage => [stage, 0]));
// Enumerate masks directly and read bits by division, not Python's product().
for (let m = 0; m < (1 << 11); m++) {
  const bits = Array.from({length:11}, (_, i) => Math.floor(m/(2**(10-i))) % 2);
  const missing = bits.findIndex(bit => bit === 0);
  const stage = missing < 0 ? stages[11] : stages[missing];
  const claim = Number(bits.slice(0,4).every(Boolean));
  const set = Number(bits.slice(0,6).every(Boolean));
  const connect = Number(bits.slice(0,7).every(Boolean));
  // Python's itertools.product runs the leftmost dimension slowest.
  const readable = bits.reduce((n,b,i) => n + b*(2**i), 0);
  lines.push(`${readable.toString(16).toUpperCase().padStart(4,'0')}|${stage}|${claim}${set}${connect}\n`);
  counts[stage]++;
}
console.log(JSON.stringify({states:lines.length, conditional_relay:counts.CONDITIONAL_RELAY,
  stage_counts:counts, sha256:createHash('sha256').update(lines.join(''),'ascii').digest('hex'),
  scope:'SYNTHETIC_SEQUENTIAL_MODEL_NOT_WIN32_EXECUTION',kernel_origin_proof:false,no_direct_proof:false}));
