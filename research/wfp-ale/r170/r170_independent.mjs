// R170 independently implemented Node.js user-mode wire oracle; no network/WFP.
function wire(family,pid,endpoint,ip){
 const b=Buffer.alloc(128);b.write('FBR3');b[4]=1;b[6]=128;
 for(let i=0;i<16;i++)b[8+i]=i+1;
 for(const [o,n] of [[24,7n],[32,BigInt(pid)],[40,314159n],[48,271828n],[56,endpoint],[64,19n],[96,987654321n]])b.writeBigUInt64LE(n,o);
 b[72]=family;b[73]=6;b.writeUInt16BE(443,74);ip.copy(b,80);return b;
}
const out=[];
for(const [family,ip] of [[4,Buffer.from('c633640a000000000000000000000000','hex')],
                          [6,Buffer.from('20010db8000000000000000000000001','hex')]])
 for(const compartment of [0,1,17,4294967295])
  for(const endpoint of [8n,999n,18446744073709551615n])
   for(const pid of [100,200]){
    const a=wire(family,pid,endpoint,ip),b=wire(family,pid,endpoint,ip);
    const x=Buffer.alloc(4),y=Buffer.alloc(4);x.writeUInt32LE(1);y.writeUInt32LE(compartment);
    out.push({family,pid,endpoint:String(endpoint),compartment,
              legacy_equal:a.equals(b),augmented_equal:Buffer.concat([a,x]).equals(Buffer.concat([b,y]))});
   }
if(out.length!==48||out.some(x=>!x.legacy_equal)||out.filter(x=>!x.augmented_equal).length!==36)
 throw Error('MODEL_FAILURE');
process.stdout.write(JSON.stringify(out)+'\n');
