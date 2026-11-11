// R117 independent Node.js oracle. No Rust import or BFE access.
import {createHash} from 'node:crypto';
const booleans=[false,true], owners=[0,1,2], values=[0,1,2,4];
const weightsEq=[0,1,3], totals=[0,1,3,7,25];
let bytes='',i=0;const counts={2:0,3:0,4:0};
for(const available of booleans) for(const owner of owners)
for(const descriptor of booleans) for(const high of values)
for(const same of weightsEq) for(const low of values)
for(const total of totals){
    let code=2;
    if(available&&owner===1&&descriptor&&total>=1 &&
       high+same+low===total-1&&total<=16384){
        code=(high!==0||same!==0||low!==0)?3:4;
    }
    bytes+=i+','+code+'\n';i++;counts[code]++;
}
if(i!==2880||Object.values(counts).some(x=>x===0)) throw Error('bad matrix');
console.log(JSON.stringify({cases:i,exit_2:counts[2],exit_3:counts[3],
    exit_4:counts[4],matrix_sha256:createHash('sha256').update(bytes).digest('hex')}));
