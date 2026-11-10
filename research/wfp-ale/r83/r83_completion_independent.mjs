// Independently derived R83 oracle; does not call any OS API.
import {createHash} from 'node:crypto';
const axes=[[0,-1,17],[0,997,10057],[0,1],[0,996,995,10022],[0,1],[0,42],[0,1]];
const hash=createHash('sha256');let n=0,counts={};
function visit(i,v){
 if(i<axes.length){for(const x of axes[i])visit(i+1,[...v,x]);return;}
 const [rc,e,r,fe,ev,bytes,same]=v;
 let label='UNKNOWN_RETAIN';
 if(rc===0||(rc===-1&&e===997&&same===1&&r===1))label='TERMINAL_OK_NO_PROOF';
 else if(rc===-1&&(e!==997||(same===1&&r===0&&fe===995)))label='TERMINAL_ERROR_NO_PROOF';
 hash.update(v.join('|')+'|'+label+'\n');n++;counts[label]=(counts[label]||0)+1;
}
visit(0,[]);
console.log(JSON.stringify({total:n,sha256:hash.digest('hex'),counts:Object.fromEntries(Object.entries(counts).sort())}));
