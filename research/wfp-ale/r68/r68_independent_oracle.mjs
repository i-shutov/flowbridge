// R68: independent bitwise oracle; deliberately does not import Python or kernel code.
// Scope is the match of TWO FlowBridge BFE filters, not a system-wide WFP verdict.
import { createHash } from 'node:crypto';
const field = (bits, index) => (bits & (1 << index)) !== 0;
const c = { all: 0, scope: [0,0,0,0,0], issue: 0, attest: 0, block_requested: 0,
  orphan_issue: 0, auth_without_issue: 0, observed_auth_without_redirect: 0,
  missing_auth_dispatch: 0, native_wfp_calls: 0, native_packets: 0 };
const hash = createHash('sha256');
for (const family of [4, 6]) {
  for (let bits=0; bits<65536; ++bits) {
    const orig = field(bits,0), cur = field(bits,1), tcp = field(bits,2);
    const selectR = cur && tcp, selectA = orig && tcp;
    const scope = !tcp ? 0 : selectR ? (selectA?4:2) : (selectA?3:1);
    // Independent explicit native-code prerequisite check (no shared all-of routine).
    const issue = selectR && field(bits,3) && field(bits,4) && field(bits,5) && field(bits,6)
      && field(bits,7) && field(bits,8) && field(bits,9)
      && field(bits,12) && field(bits,13) && field(bits,14);
    const att = issue && orig && field(bits,10) && field(bits,11) && field(bits,15);
    const requested = selectA && field(bits,15) && !att;
    const orphan = issue && !selectA;
    const authOnly = selectA && field(bits,15) && !selectR;
    c.all++; c.scope[scope]++; c.issue += Number(issue); c.attest += Number(att);
    c.block_requested += Number(requested); c.orphan_issue += Number(orphan);
    c.auth_without_issue += Number(authOnly);
    c.observed_auth_without_redirect += Number(scope === 3 && requested);
    c.missing_auth_dispatch += Number(orphan);
    hash.update(`${family}|${bits}|${scope}|${Number(issue)}|${Number(att)}|${Number(requested)}|${Number(orphan)}|${Number(authOnly)}\n`);
  }
}
console.log(JSON.stringify({families:[4,6],states:c.all,scope:c.scope,issue:c.issue,attest:c.attest,
 block_requested:c.block_requested,orphan_issue:c.orphan_issue,auth_without_issue:c.auth_without_issue,
 observed_auth_without_redirect:c.observed_auth_without_redirect,missing_auth_dispatch:c.missing_auth_dispatch,
 decision_sha256:hash.digest('hex'), native_wfp_calls:0,native_packets:0},null,2));
