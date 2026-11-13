#!/usr/bin/env node
// Independent FBR3 projection using DataView; no Python source import.
import assert from 'node:assert/strict';
function fixture(family) {
  return {family, pid:111, epoch:222, start_key:333, endpoint:444,
    owner_generation:1, sequence:1, stamp:9876543,port:443,
    destination:family===4?Buffer.from('cb007108000000000000000000000000','hex')
      :Buffer.from('20010db8000000000000000000000008','hex'),
    compartment:1,parent_endpoint:0,remote_scope:0};
}
function encode(f) {
  const v=Buffer.alloc(128);
  Buffer.from('FBR3\x01\x00\x80\x00','binary').copy(v,0);
  Buffer.from('00112233445566778899aabbccddeeff','hex').copy(v,8);
  const d=new DataView(v.buffer,v.byteOffset,v.byteLength);
  for(const [offset,key] of [[24,'sequence'],[32,'pid'],[40,'epoch'],[48,'start_key'],
                             [56,'endpoint'],[64,'owner_generation'],[96,'stamp']])
     d.setBigUint64(offset,BigInt(f[key]),true);
  v[72]=f.family;v[73]=6;d.setUint16(74,f.port,false);f.destination.copy(v,80);
  return v;
}
const matrix=[];
for(const family of [4,6]) {
 const base=fixture(family);
 for(const [dimension,values] of [['compartment',[2,7,101]],
              ['parent_endpoint',[2,777,2**40]],['remote_scope',[2,7,101]]]){
   for(const value of values){
     const other={...base,[dimension]:value};
     matrix.push({family,dimension,value,same_context:encode(base).equals(encode(other))});
   }
 }
 for(const key of ['pid','epoch','start_key','endpoint','owner_generation','sequence','stamp','port'])
   assert(!encode(base).equals(encode({...base,[key]:base[key]+1})),key);
 assert(!encode(base).equals(encode({...base,destination:Buffer.from(base.destination.map((v,i)=>i===15?v^1:v))})));
}
assert.equal(matrix.length,18);
assert(matrix.every(x=>x.same_context));
if(process.argv[2]==='--matrix')console.log(JSON.stringify(matrix));
else console.log('INDEPENDENT_FBR3_PROJECTION_PASS 18/18');
