#!/usr/bin/env node
// Independently constructed full enumeration; not importing Python model.
import { createHash } from 'node:crypto';
const result = {
  states:0, claim:0, full_evidence:0, claim_without_socket_pair:0,
  claim_without_wfp_query:0, claim_with_reused_tuple:0,
  claim_with_sibling_direct:0, claim_with_ssh_loss:0,
};
const digest = createHash('sha256');
for (const ipVersion of [4,6]) {
  for(let n=0; n<65536; ++n) {
    // Source conditions (0..10) versus missing observable properties (11..15).
    const mandatoryMask=(1<<11)-1;
    const accepted=(n&mandatoryMask)===mandatoryMask;
    const complete=accepted && (n>>11)===31;
    const property=(j)=>(n&(1<<j))!==0;
    ++result.states;
    if(accepted) ++result.claim;
    if(complete) ++result.full_evidence;
    if(accepted&&!property(11)) ++result.claim_without_socket_pair;
    if(accepted&&!property(12)) ++result.claim_without_wfp_query;
    if(accepted&&!property(13)) ++result.claim_with_reused_tuple;
    if(accepted&&!property(14)) ++result.claim_with_sibling_direct;
    if(accepted&&!property(15)) ++result.claim_with_ssh_loss;
    digest.update(`${ipVersion}:${String(n).padStart(5,'0')}:${Number(accepted)}:${Number(complete)}\n`);
  }
}
result.decision_sha256=digest.digest('hex');
process.stdout.write(JSON.stringify(Object.fromEntries(Object.entries(result).sort(([a],[b])=>a.localeCompare(b))))+'\n');
