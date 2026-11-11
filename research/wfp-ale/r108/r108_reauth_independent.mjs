// Independent bit-enumeration oracle for R108. No OS interaction.
import {createHash} from 'node:crypto';
const reasons=['INITIAL','POLICY_CHANGE','NEW_INTERFACE','CLASSIFY_COMPLETION','SOCKET_PROPERTY'];
const rows=[];let permitted=0, reauthQualifiedBlocked=0;
for (const family of [4,6]) for (const reason of reasons) {
  for (let state=0;state<32;state++) {
    const write=(state>>>4)&1, metadata=(state>>>3)&1, redirected=(state>>>2)&1,
      origin=(state>>>1)&1, ticket=state&1;
    const reauth=(reason==='INITIAL')?0:1;
    const permittedByR19=(write & metadata & redirected & origin & ticket & (1-reauth));
    permitted+=permittedByR19;
    if(reauth && (write & metadata & redirected & origin & ticket)) reauthQualifiedBlocked++;
    rows.push([family,reason,write,metadata,redirected,origin,ticket,permittedByR19].join('|'));
  }
}
if(rows.length!==320||permitted!==2||reauthQualifiedBlocked!==8)throw Error('oracle invariant failure');
const raw=rows.join('\n')+'\n';
console.log(`states=${rows.length} permitted=${permitted} reauth_block_with_all_other_gates_valid=${reauthQualifiedBlocked} sha256=${createHash('sha256').update(raw).digest('hex')}`);
