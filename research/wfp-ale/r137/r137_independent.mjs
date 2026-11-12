// Independent truth-table computation. No Python/Rust imported.
import {createHash} from 'node:crypto';
const rows=[]; const totals={'0':0,'3':0,'4':0};
for(let value=0;value<256;value++) {
  const f = Array.from({length:8},(_,j)=>Boolean((value>>j)&1));
  const ready=f.slice(0,4).every(Boolean);
  let exit=3;
  if(ready) {
    if(!f[4])exit=4;
    else if(f[5])exit=0;
  }
  rows.push(String(value).padStart(3,'0')+':'+exit+'\n');
  totals[String(exit)]++;
}
console.log(JSON.stringify({states:rows.length,diagnostic_exit_counts:totals,
 sha256:createHash('sha256').update(rows.join(''),'ascii').digest('hex')}));
