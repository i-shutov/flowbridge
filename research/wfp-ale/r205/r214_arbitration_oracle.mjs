// R214 independent Node oracle: enumeration of evidence state, not WFP execution.
import assert from 'node:assert/strict';
const families = ['V4', 'V6'];
const finalOutcomes = ['PERMIT', 'VETO_BLOCK', 'OTHER_LAYER_BLOCK'];
let total = 0, conditionalGaps = 0;
for (const family of families) {
  for (const validAuth of [false, true]) {
    for (const finalAction of finalOutcomes) {
      // Independent state machine: local AUTH callback mutates book and returns;
      // filtering engine then arbitrates across sublayers/layers.
      const log = [];
      let book = { issued: true, authSeen: false, consumed: false };
      if (validAuth) {
        book.authSeen = true;
        log.push('LOCAL_ATTEST');
        log.push('LOCAL_HARD_PERMIT');
      } else {
        log.push('LOCAL_BLOCK');
      }
      log.push('FINAL_' + finalAction);
      const possibleTicketConsumeGivenSocketReceipt = book.issued && book.authSeen && !book.consumed;
      if (possibleTicketConsumeGivenSocketReceipt) book.consumed = true;
      const endToEndAuthorized = validAuth && finalAction === 'PERMIT';
      if (validAuth && finalAction !== 'PERMIT') {
        assert.equal(possibleTicketConsumeGivenSocketReceipt, true);
        assert.equal(endToEndAuthorized, false);
        assert.equal(log[0], 'LOCAL_ATTEST');
        conditionalGaps++;
      } else {
        assert.equal(possibleTicketConsumeGivenSocketReceipt, validAuth);
        assert.equal(endToEndAuthorized, validAuth && finalAction === 'PERMIT');
      }
      assert.ok(['V4', 'V6'].includes(family));
      total++;
    }
  }
}
assert.equal(total, 12);
assert.equal(conditionalGaps, 4);
console.log('R214 independent oracle: ' + total + '/12 states PASS, ' + conditionalGaps + ' conditional evidence-vs-disposition divergences; native reachability UNKNOWN');
