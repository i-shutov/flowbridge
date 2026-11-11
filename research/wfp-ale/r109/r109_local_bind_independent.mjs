/** R109 independent Node.js oracle, synthetic Windows local address state.
 * No sockets, dynamic imports, OS API or network. */
import {createHash} from 'node:crypto';
import {isIP} from 'node:net';

const addresses = [
  [4,'0.0.0.0'],[4,'127.0.0.1'],[4,'127.0.0.2'],
  [4,'10.20.30.40'],[4,'192.0.2.7'],[4,'0.0.0.1'],
  [6,'::'],[6,'::1'],[6,'::2'],
  [6,'2001:db8::5'],[6,'fe80::1'],[6,'::ffff:192.0.2.7']
];
const safeLocal = new Map([[4,new Set(['0.0.0.0','127.0.0.1'])],[6,new Set(['::','::1'])]]);
const rows=[];
for (const [family, local] of addresses) {
  if (isIP(local)!==family) throw new Error('invalid input');
  for (const port of [443,8443]) {
    for (const lease of [false,true]) {
      // Independently apply the source-verified exact allowlist; do not re-use
      // Python's socket byte parser or Python's implementation.
      const action = !lease ? 'BLOCK_LEASE' :
        (safeLocal.get(family).has(local) ? 'TRY_REDIRECT' : 'BLOCK_LOCAL');
      rows.push({family,local,port,lease,action});
    }
  }
}
// Python sort_keys=True: action, family, lease, local, port alphabetical.
const encoded=rows.map(({family,local,port,lease,action})=>
  JSON.stringify({action,family,lease,local,port})).join('\n')+'\n';
const sha256=createHash('sha256').update(encoded).digest('hex');
const counts=Object.fromEntries(['TRY_REDIRECT','BLOCK_LOCAL','BLOCK_LEASE'].map(k=>[k,rows.filter(x=>x.action===k).length]));
if (rows.length!==48 || counts.TRY_REDIRECT!==8 || counts.BLOCK_LOCAL!==16 || counts.BLOCK_LEASE!==24) throw new Error('mismatched counts');
console.log(JSON.stringify({test:'R109 Node',cases:rows.length,counts,sha256}));
