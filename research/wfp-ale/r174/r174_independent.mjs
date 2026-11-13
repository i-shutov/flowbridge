import assert from 'node:assert/strict';
const o={pid:101,epoch:202,key:303,endpoint:404,generation:1};
function observation(p,run,index,ipVersion,image){
  return JSON.stringify({session:run,receipt:index,endpoint:p.endpoint,pid:p.pid,
    epoch:p.epoch,start:p.key,ownerGeneration:p.generation,family:ipVersion,
    flags:15,protocol:6,appid:image});
}
function ticket(p,s,n,f,ip,port,time){
  return JSON.stringify({session:s,seq:n,pid:p.pid,epoch:p.epoch,start:p.key,
    endpoint:p.endpoint,generation:p.generation,family:f,protocol:6,ip,port,issued:time});
}
function history(prior){
  let sequence=0,receipt=0;const used=new Set();
  if(prior){assert(!used.has(405));used.add(405);sequence++;}
  assert(!used.has(o.endpoint));used.add(o.endpoint);sequence++;receipt++;
  return {w:observation(o,93,receipt,4,'selected.exe'),
    c:ticket(o,'a'.repeat(32),sequence,4,'192.0.2.1',443,100),n:used.size};
}
const a=history(false),b=history(true);
assert.equal(a.w,b.w);assert.notEqual(a.c,b.c);
assert.deepEqual([a.n,b.n],[1,2]);
const rows=[];
for(const [f,ip1,ip2] of [[4,'192.0.2.1','192.0.2.2'],
                            [6,'2001:db8::1','2001:db8::2']])
for(const ledgerSession of [1,2,65535])
for(const receipt of [1,5,33])
for(const kind of ['destination','port','sequence','book_session','issued_at']){
  const w1=observation(o,ledgerSession,receipt,f,'selected.exe');
  const w2=observation(o,ledgerSession,receipt,f,'selected.exe');
  const c1=ticket(o,'a'.repeat(32),1,f,ip1,443,100);
  const args={destination:['a'.repeat(32),1,ip2,443,100],
              port:['a'.repeat(32),1,ip1,8443,100],
              sequence:['a'.repeat(32),2,ip1,443,100],
              book_session:['b'.repeat(32),1,ip1,443,100],
              issued_at:['a'.repeat(32),1,ip1,443,101]};
  const [s,n,ip,port,time]=args[kind];
  const c2=ticket(o,s,n,f,ip,port,time);
  assert.equal(w1,w2);assert.notEqual(c1,c2);
  rows.push({case:`${f}-${ledgerSession}-${receipt}-${kind}`,
    context_equal:c1===c2,context_fields:12,
    witness_equal:w1===w2,witness_fields:11});
}
assert.equal(rows.length,90);
for(const r of rows)console.log(JSON.stringify(r));
