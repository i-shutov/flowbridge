// Independent offline oracle for R189. No WFP, drivers, filters, or sockets.
import {createHash} from 'node:crypto';
const h=createHash('sha256');
const out={rows:0,naive_green:0,stale_or_unknown:0,unsafe_certificate:0};
for(const family of [4,6])for(const proto of ['tcp','udp'])
for(const scope of ['selected','sibling'])for(const grant of [0,1])
for(const direction of ['out','in'])for(const queued of [0,1])
for(const phase of ['not_detected','detected_idle','reauth_blocked'])
for(const loss of ['stable','bfe_lost','ssh_lost']){
 const oldFlow=Number(proto==='tcp'&&scope==='selected'&&grant===1);
 const green=oldFlow;
 const uncertain=Number(Boolean(oldFlow)&&(phase!=='reauth_blocked'||queued===1||loss!=='stable'));
 const certificate=0;
 h.update([family,proto,scope,grant,direction,queued,phase,loss,green,uncertain,certificate].join(',')+'\n');
 out.rows++;out.naive_green+=green;out.stale_or_unknown+=uncertain;
 out.unsafe_certificate+=green*(1-certificate);
}
const expected={rows:576,naive_green:72,stale_or_unknown:68,unsafe_certificate:72};
if(Object.keys(expected).some(k=>out[k]!==expected[k]))throw Error('R189 matrix disagrees');
const payload={counts:out,matrix_sha256:h.digest('hex'),native_windows:false};
console.log(JSON.stringify(payload));
