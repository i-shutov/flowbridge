// Independent Node oracle: 512 rows built from actual distinct UTF-16 AppId blobs.
// Never launches a process, asks BFE, changes firewall, or opens sockets.
import {createHash} from 'node:crypto';
const aid=(c)=>Buffer.from('\\device\\harddiskvolume3\\apps\\'+c+'.exe'+'\0','utf16le');
const ids=[aid('a'),aid('b')];
if(ids[0].equals(ids[1]) || ids[0].length!==ids[1].length)throw Error('not an equal-size negative');
const n={total:0,old_pass:0,strict_pass:0,false_positive:0,false_negative:0};
const hash=createHash('sha256');
for(let path=0;path<2;path++){
  for(let structure=0;structure<16;structure++){
    for(let equality=0;equality<16;equality++){
      let old=true, strict=true;
      for(let i=0;i<4;i++){
        const observed=(equality & (1<<i))?ids[path]:ids[1-path];
        old &&= !!(structure & (1<<i)) && observed.length>=4 && observed.length<=514 && observed.length%2===0;
        strict &&= !!(structure & (1<<i)) && observed.equals(ids[path]);
      }
      old=+old;strict=+strict;
      n.total++;n.old_pass+=old;n.strict_pass+=strict;
      n.false_positive+=old*(1-strict);n.false_negative+=strict*(1-old);
      hash.update([path,structure,equality,old,strict].join(',')+'\n');
    }
  }
}
if(JSON.stringify(n)!==JSON.stringify({total:512,old_pass:32,strict_pass:2,false_positive:30,false_negative:0}))throw Error('bad outcome');
console.log(JSON.stringify({count:n,matrix_sha256:hash.digest('hex'),rust_source_gate:true}));
