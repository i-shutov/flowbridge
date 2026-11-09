// R62 independent Node oracle. Synthetic bits, no Windows/driver/network use.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const fields = [
 'ipv6','selected_origin','endpoint_appid_selected',
 'matching_redirect_record','hypothetical_native_socket_join',
 'pid_epoch_verified','one_use_ticket','original_appid_verified',
 'ssh_wfp_ready','exit_observation_alive','physically_alive',
 'duplicated_socket','endpoint_id_equal','query_succeeded','callback_dispatched'
];
const result={states:32768,undispatched:0,weak:0,strict:0,weak_excess:0,
 weak_sibling:0,weak_wrong_record:0,weak_no_join:0,
 strict_after_physical_death:0,strict_different_endpoint_id:0,
 strict_duplicated_socket:0};
const hash=createHash('sha256');
for(let i=0; i<32768; i++) {
 const x=Object.fromEntries(fields.map((k,j)=>[k,!!(i & (1<<j))]));
 if(!x.callback_dispatched){result.undispatched++;hash.update(`${i}|N|N\n`);continue;}
 // Deliberately separate implementation: weak broker-only receipt checks.
 const weak = x.one_use_ticket && x.original_appid_verified && x.ssh_wfp_ready &&
              x.exit_observation_alive && x.query_succeeded;
 // Counterfactual kernel-attested join is not implemented or documented.
 const strict = weak && x.selected_origin && x.matching_redirect_record &&
               x.hypothetical_native_socket_join && x.pid_epoch_verified;
 hash.update(`${i}|${+weak}|${+strict}\n`);
 if(weak){
   result.weak++;
   if(!x.selected_origin)result.weak_sibling++;
   if(!x.matching_redirect_record)result.weak_wrong_record++;
   if(!x.hypothetical_native_socket_join)result.weak_no_join++;
 }
 if(strict){
   result.strict++;
   if(!x.physically_alive)result.strict_after_physical_death++;
   if(!x.endpoint_id_equal)result.strict_different_endpoint_id++;
   if(x.duplicated_socket)result.strict_duplicated_socket++;
 }
 if(weak&&!strict)result.weak_excess++;
}
result.decision_sha256=hash.digest('hex');
if(result.weak!==512 || result.strict!==32 || result.weak_excess!==480 ||
   result.undispatched!==16384)throw Error('R62 invariant mismatch');
console.log(JSON.stringify(result,null,2));
writeFileSync(new URL('node_result.json',import.meta.url),JSON.stringify(result,null,2)+'\n');
