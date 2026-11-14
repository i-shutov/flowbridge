// R175 separate declarative reference: no mutation of a Ledger queue.
// Derives dispatcher-visible outputs from an immutable sequence of observations.
const kinds=['dead-first','live-first','alternating'];
function order(kind,d,l){
  if(kind==='dead-first')return [...Array(d).fill('D'),...Array(l).fill('L')];
  if(kind==='live-first')return [...Array(l).fill('L'),...Array(d).fill('D')];
  let a=[];for(let i=0;i<Math.max(d,l);i++){if(i<d)a.push('D');if(i<l)a.push('L')};return a;
}
const rows=[];
for(const family of [4,6])for(const kind of kinds)for(let d=1;d<=4;d++)for(let l=0;l<4;l++){
  const seq=order(kind,d,l);
  const status=seq.map(p=>p==='D'?'NOT_READY':'SUCCESS').concat('EMPTY');
  const visible_receipts=seq.flatMap((p,i)=>p==='L'?[i+1]:[]);
  rows.push({case:family+"/"+kind+"/"+d+"/"+l,family,initial_receipts:seq.length,
    status,visible_receipts,lost:false,opaque_errors:d,tail:'EMPTY'});
}
if(rows.length!==96||!rows.every(r=>r.opaque_errors>0&&r.tail==='EMPTY'&&!r.lost))throw Error('matrix cardinality');
// Python uses sort_keys. Canonical lexicographically ordered keys in JS.
for(const r of rows){const obj={};for(const k of Object.keys(r).sort())obj[k]=r[k];console.log(JSON.stringify(obj));}
