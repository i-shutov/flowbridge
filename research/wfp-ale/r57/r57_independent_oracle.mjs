// Independent R57 Boolean lattice oracle; Node built-ins only. No WFP or sockets.
// Implementation deliberately works from forbidden-evidence sets, not Python formula.
import { createHash } from 'node:crypto';
const bitNames = ['bfe', 'allow_reclassify', 'conditional', 'flow_context', 'kernel_origin',
  'session', 'epoch', 'appid', 'endpoint', 'ticket', 'flow_scope', 'owner_live', 'ssh_live', 'not_tombstoned'];
const stages = ['initial', 'socket_reclass', 'completion', 'policy'];
const result = Object.fromEntries(stages.map(k => [k, { dispatch_candidate: 0, guarded_model_permit: 0, current_reauth_flag_gate_upper_bound: 0, weak_permit: 0 }]));
const h = createHash('sha256');
const missing = (flags, name) => (flags & (1 << bitNames.indexOf(name))) === 0;
for (const ip of [4, 6]) {
  for (const stage of stages) {
    const counts = result[stage];
    for (let mask = 0; mask < (1 << bitNames.length); ++mask) {
      const unseen = missing(mask, 'bfe') || (!missing(mask, 'conditional') && missing(mask, 'flow_context')) ||
        (stage === 'socket_reclass' && missing(mask, 'allow_reclassify'));
      const dispatched = !unseen;
      let rejected = unseen;
      for (const field of ['kernel_origin', 'session', 'epoch', 'appid', 'endpoint', 'ticket', 'owner_live', 'ssh_live', 'not_tombstoned']) {
        if (missing(mask, field)) rejected = true;
      }
      if (stage !== 'initial' && (missing(mask, 'flow_context') || missing(mask, 'flow_scope'))) rejected = true;
      const currentRejected = (stage !== 'initial') || rejected;
      const weak = dispatched && (stage === 'initial' || !missing(mask, 'flow_context'));
      const row = [Number(dispatched), Number(!rejected), Number(!currentRejected), Number(weak)];
      h.update(Buffer.from(row));
      for (const [j, key] of ['dispatch_candidate', 'guarded_model_permit', 'current_reauth_flag_gate_upper_bound', 'weak_permit'].entries()) counts[key] += row[j];
    }
  }
}
console.log(JSON.stringify({cases: 2 * stages.length * 2 ** bitNames.length, per_stage: result,
  sha256_byte_vector: h.digest('hex'), family_count: 2, fields: bitNames.length}));
