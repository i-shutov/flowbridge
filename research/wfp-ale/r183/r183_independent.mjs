// R183 independent Node.js parser of the actual Python-produced crash journal bytes.
// No network, sockets, WFP or Windows APIs. Requires Node >= 18.
import {readFileSync} from 'node:fs';
const folder=process.argv[2];
if(!folder)throw Error('usage: node r183_independent.mjs DIRECTORY');
const kinds=['grant','ack','claim'];
function permute(values,prefix=[]){if(!values.length)return [prefix];return values.flatMap((item,i)=>permute(values.filter((_,j)=>i!==j),[...prefix,item]));}
function crc32(data){let c=0xffffffff;for(const b of data){c^=b;for(let i=0;i<8;i++)c=(c>>>1) ^ ((c&1)?0xedb88320:0);}return(c^0xffffffff)>>>0;}
function parse(bytes){let off=0;const events=[];while(off<bytes.length){
 if(off+8>bytes.length)throw Error('partial_header');
 const n=bytes.readUInt32LE(off),checksum=bytes.readUInt32LE(off+4);off+=8;
 if(!n||n>2048||off+n>bytes.length)throw Error('size');
 const body=bytes.subarray(off,off+n);off+=n;
 if(crc32(body)!==checksum)throw Error('crc');
 const e=JSON.parse(body.toString('utf8'));
 if(e.tx!=='kernel-tx-1'||e.session!=='broker-session-5'||!kinds.includes(e.event))throw Error('fields');
 events.push(e.event);
 }return events;
}
for(const family of ['v4','v6']){
 for(const [index,order] of permute(kinds).entries()){
  const bytes=readFileSync(folder+'/'+family+'_'+index+'.bin');
  const parsed=parse(bytes),legacy=kinds.every(k=>parsed.includes(k));
  const safe=parsed.length===3 && kinds.every((v,i)=>parsed[i]===v);
  if(parsed.join('>')!==order.join('>'))throw Error('fixture/order mismatch');
  // Lexicographic object order matches Python sort_keys=True JSON serializer.
  console.log(JSON.stringify({family,legacy,order:parsed.join('>'),safe}));
 }
}
