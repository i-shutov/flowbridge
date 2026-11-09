// Independent bitmask oracle; deliberately does not import the Python model.
import { createHash } from 'node:crypto';
const sha = createHash('sha256');
const count = {states:0,kernel:0,typed:0,physical:0,kernel_without_pair:0,raw_bypass_candidate:0};
for (const family of [4,6]) {
  for(let word=0;word<2048;word++) {
    // Ordering fixed by Python State dataclass declaration.
    const has = (bit) => Boolean(word & (1<<bit));
    const kernel = (word & 0b1111) === 0b1111;
    const typed = kernel && (word & 0b1110000) === 0b1110000 &&
       has(7) && !has(8);
    const physical = typed && has(9) && has(10);
    const decision = (Number(kernel) | Number(typed)<<1 | Number(physical)<<2);
    sha.update(Buffer.from([decision]));
    count.states++;count.kernel += Number(kernel);count.typed += Number(typed);
    count.physical += Number(physical);
    count.kernel_without_pair += Number(kernel && !has(4));
    count.raw_bypass_candidate += Number(kernel && has(8));
  }
}
console.log('R73 stream_sha256=' + sha.digest('hex'));
console.log('R73 counts=' + JSON.stringify(count));
