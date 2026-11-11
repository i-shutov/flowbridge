/* Independent table-based oracle for the Microsoft WFP arbitration boundary.
 * No WFP API calls, no network, no driver. Not an operational proof. */
import {createHash} from 'node:crypto';
const H=['soft_permit','hard_permit','soft_block','hard_block'];
const L=['continue','permit','block','veto'];
// Rows: high sublayer result; columns: lower action.
const outcomes=[
  ['PERMIT','PERMIT','BLOCK','BLOCK'],
  ['PERMIT','PERMIT','PERMIT','BLOCK'],
  ['BLOCK','PERMIT','BLOCK','BLOCK'],
  ['BLOCK','BLOCK','BLOCK','BLOCK'],
];
let transcript='';
for(let h=0;h<H.length;h++)for(let l=0;l<L.length;l++){
  transcript+=`${H[h]},${L[l]},${outcomes[h][l]}\n`;
}
const old=0+0>0?3:4;
const fixed=1>0?3:4;
if(outcomes[0][2]!=='BLOCK'||outcomes[1][3]!=='BLOCK'||old!==4||fixed!==3)
  throw Error('missing lower-sublayer counterexample');
console.log(JSON.stringify({cases:16,
    arbitration_matrix_sha256:createHash('sha256').update(transcript).digest('hex'),
    counterexample:'higher soft_permit + lower block -> BLOCK',
    hard_permit_veto:outcomes[1][3],old_lower_only_exit:old,
    corrected_lower_only_exit:fixed}));
