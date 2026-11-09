// R78 independent algebraic oracle; no network, Windows APIs or dependencies.
import {createHash} from 'node:crypto';
let sum=createHash('sha256'), counts={DROP:0,SCHEDULE:0};
for(const family of [4,6])for(const cap of [1,2,4,32]){
  for(let bogus=0;bogus<cap+2;bogus++)for(let completed=0;completed<cap+2;completed++){
    for(const real of [0,1]){
      const admitted=Math.min(bogus,cap-real);
      const outstanding=Math.max(0,admitted-completed);
      const deny=(outstanding+real===cap);
      const verdict=deny?'DROP':'SCHEDULE';
      const drops=Math.max(0,bogus-(cap-real))+(deny?1:0);
      counts[verdict]++;
      sum.update(`${family},${cap},${bogus},${completed},${real}|${verdict}|${drops}\n`);
    }
  }
}
console.log(JSON.stringify({cases:counts.DROP+counts.SCHEDULE,outcomes:counts,sha256:sum.digest('hex')}));
