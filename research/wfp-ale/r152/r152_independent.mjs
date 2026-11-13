// Independent JavaScript oracle for hypothetical endpoint-handle ABA.
// No Python imports, kernel, network or WFP operations.
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const h=createHash('sha256');
let states=0, aliases=0, twins=0, delayedAccepted=0, freshAccepted=0, weakerAlias=0;
for (const family of [4,6]) {
  for(let mask=0;mask<64;mask++) {
    const epoch= (mask>>5)&1, app=(mask>>4)&1, compartment=(mask>>3)&1;
    const destination=(mask>>2)&1, sameHandle=(mask>>1)&1, stale=mask&1;
    const old={app:'selected',epoch:100,pid:501,start:300,handle:71,
      family, compartment:9,dest:'198.51.100.10:443'};
    const next={app:app?'selected':'sibling',epoch:epoch?100:101,pid:501,
      start:epoch?300:301,handle:sameHandle?71:72,family,
      compartment:compartment?9:10,
      dest:destination?'198.51.100.10:443':'198.51.100.11:443'};
    const presented=stale?old:next;
    const equal=Object.keys(next).every(k=>next[k]===presented[k]);
    const quarantined=Boolean(sameHandle);
    const hypNonce=(stale?1:2)===2;
    const accepted=equal;
    const alias=Boolean(stale && accepted);
    const weaker=Boolean(next.app==='selected' && presented.app==='selected' &&
       next.pid===presented.pid && next.epoch===presented.epoch && next.start===presented.start &&
       next.handle===presented.handle && next.family===presented.family && next.dest===presented.dest);
    if(stale && weaker) weakerAlias++;
    assert.equal(accepted, !stale || Boolean(epoch&&app&&compartment&&destination&&sameHandle));
    assert.equal(hypNonce,!stale);
    if (alias) aliases++;
    if (stale && accepted) delayedAccepted++;
    if (!stale&&accepted) freshAccepted++;
    if (epoch&&app&&compartment&&destination&&sameHandle) {
      twins++;
      assert.equal(quarantined,true);
    }
    const label=`${family}|${epoch}${app}${compartment}${destination}${sameHandle}${stale}|${Number(accepted)}|${Number(!quarantined)}|${Number(hypNonce)}|${Number(alias)}|${Number(weaker)}\n`;
    h.update(label,'ascii'); states++;
  }
}
assert.deepEqual([states,aliases,twins,delayedAccepted,freshAccepted,weakerAlias],[128,2,4,2,64,4]);
console.log(JSON.stringify({states,stale_auth_alias:aliases,indistinguishable_rows:twins,
  fresh_auth_accepted_by_naive:freshAccepted,stale_auth_accepted_by_naive:delayedAccepted,stale_auth_matches_r19_book_shape:weakerAlias,
  sha256:h.digest('hex'),native_windows_proof:false,no_direct_proved:false,release_accepted:false}));
