// Independent frequency/spec oracle; no Python import, network, or Windows API.
import {createHash} from 'node:crypto';
const outcomes = ['present','missing','denied','error','invalid'];
const rows = [], counts = {'2':0,'3':0,'4':0,'5':0};
// Fixed-base counter ordering, rather than the Python product traversal.
for (let n=0;n<625;n++) {
  const digits=[Math.floor(n/125)%5,Math.floor(n/25)%5,Math.floor(n/5)%5,n%5];
  const tally=Object.fromEntries(outcomes.map(k=>[k,0]));
  for (const d of digits) tally[outcomes[d]]++;
  for (const close of [0,1]) {
    let exit=2;
    if (close===0 && tally.error===0 && tally.invalid===0) {
      exit=tally.denied ? 5 : tally.missing ? 4 : 3;
    }
    counts[exit]++;
    rows.push(`${digits.join('')}:${close}:${exit}\n`);
  }
}
if(rows.length!==1250 || counts['3']!==1 || counts['4']!==15 || counts['5']!==65 || counts['2']!==1169) throw Error('count regression');
console.log(JSON.stringify({states:rows.length,exits:counts,sha256:createHash('sha256').update(rows.join('')).digest('hex')}));
