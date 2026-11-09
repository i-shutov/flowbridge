// R74 independent Node stdlib enumerator, not a Windows/driver experiment.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const keys=['selected','receipt','claim','records','tcp','host','auth','channel','revoked',
  'owner_alive','endpoint_reused_after_claim','ssh_loss','wfp_loss'];
function policy(b) {
  if(!b.receipt) return ['INGRESS_REJECTED',false,false,false];
  if(!b.claim) return ['STICKY_STOP',false,false,false];
  if(!b.records||!b.tcp||!b.host||!b.auth||!b.channel||b.revoked||b.ssh_loss)
    return ['STICKY_STOP',true,false,false];
  return ['RELAY_CANDIDATE',true,true,false];
}
const totals={worlds:0,pre_receipt_selected_silent:0,pre_receipt_unselected:0,
  post_receipt_stop:0,relay_candidate:0,claimed_terminal_failed:0,
  selected_owner_dead_relay_candidate:0,endpoint_reused_after_claim_relay_candidate:0,
  wfp_lost_relay_candidate:0,no_direct_proven:0};
const h=createHash('sha256');
for(const family of [4,6]){
  for(let code=0;code<8192;code++){
    const b=Object.fromEntries(keys.map((k,i)=>[k,!!(code & (1<<(12-i)))]));
    const [stage,terminal,release,physical]=policy(b);
    const strict=b.selected&&!b.receipt?'STICKY_STOP':stage;
    totals.worlds++;
    totals.pre_receipt_selected_silent+=+(b.selected&&!b.receipt&&stage==='INGRESS_REJECTED'&&strict==='STICKY_STOP');
    totals.pre_receipt_unselected+=+(!b.selected&&!b.receipt&&stage==='INGRESS_REJECTED');
    totals.post_receipt_stop+=+(b.receipt&&stage==='STICKY_STOP');
    totals.relay_candidate+=+release;
    totals.claimed_terminal_failed+=+(terminal&&!release);
    totals.selected_owner_dead_relay_candidate+=+(release&&b.selected&&!b.owner_alive);
    totals.endpoint_reused_after_claim_relay_candidate+=+(release&&b.endpoint_reused_after_claim);
    totals.wfp_lost_relay_candidate+=+(release&&b.wfp_loss);
    totals.no_direct_proven+=+physical;
    const bits=keys.map(k=>Number(b[k])).join('');
    h.update(`${family}:${bits}:${stage}:${Number(terminal)}:${Number(release)}:${strict}\n`);
  }
}
assert.equal(totals.worlds,16384);
const sha256=h.digest('hex');
assert.equal(sha256,'ba9534ef412fda18d6ddf37cddd414ab0b97cbcaff4875a8f4aab797be71855f');
assert.equal(totals.pre_receipt_selected_silent,4096);
assert.equal(totals.no_direct_proven,0);
console.log(JSON.stringify({counts:totals,sha256}));
