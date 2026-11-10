// R92 independent, exhaustive filter-set observation oracle.
// This is not a Windows network or policy enforcement test.
import {createHash} from 'node:crypto';
const lines=[];
let gaps=0, noBarrier=0;
for (let mask=0; mask<16; mask++) {
  for (let notified=0; notified<=1; notified++) {
    for (let lease=0; lease<=1; lease++) {
      for (let broker=0; broker<=1; broker++) {
        for (let ticket=0; ticket<=1; ticket++) {
          for (let barrier=0; barrier<=1; barrier++) {
            const alive=Number(lease===1 && broker===1 && ticket===1);
            const isActive=bit=>Boolean(mask & (1 << bit));
            const absent4=Number(!isActive(0) || !isActive(1));
            const absent6=Number(!isActive(2) || !isActive(3));
            const cannotCertify=Number(Boolean(alive && (absent4 || absent6)));
            const unguarded=Number(Boolean(cannotCertify && barrier===0));
            gaps+=cannotCertify; noBarrier+=unguarded;
            lines.push([mask,notified,lease,broker,ticket,barrier,alive,absent4,
              absent6,cannotCertify,unguarded].join(','));
          }
        }
      }
    }
  }
}
if(lines.length!==512 || gaps===0 || noBarrier===0) throw Error('oracle census');
const digest=createHash('sha256').update(lines.join('\n')+'\n').digest('hex');
console.log('ROWS',lines.length);
console.log('SHA256',digest);
console.log('UNVERIFIED_POLICY',gaps);
console.log('NO_INDEPENDENT_BARRIER',noBarrier);
