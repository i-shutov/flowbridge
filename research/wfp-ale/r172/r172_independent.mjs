#!/usr/bin/env node
// Independent finite-state oracle. No dependencies, Windows APIs or network.
// Models privileged non-broker witness reader as allowed by SDDL + FILE_READ_DATA.
for (const producer of [false,true])
for (const live of [false,true])
for (const lost of [false,true])
for (const family of [4,6])
for (const epoch of [1,2])
for (const reused of [false,true])
for (const [one,two] of [
    ['broker','admin_other'], ['admin_other','broker'],
    ['standard','broker'], ['broker','standard'],
    ['admin_other','admin_other'], ['broker','broker']]) {
  let available=producer ? 1 : 0;
  let results=[];
  for(const who of [one,two]) {
    // Authorization is a handle right, not a process-identity check.
    if(who==='standard'){results.push('ACCESS_DENIED');continue;}
    if(lost){results.push('NOT_READY');continue;}
    if(!available){results.push('EMPTY');continue;}
    available=0;
    results.push(live?'SUCCESS':'NOT_READY');
  }
  const record={producer:Number(producer),live:Number(live),lost:Number(lost),
    family,epoch,tuple_reused:Number(reused),order:one+'/'+two,
    outcomes:results.join('/'),queue:available};
  // Exact Python json.dumps(sort_keys=True,separators=(',',':')) property order.
  const sorted=Object.fromEntries(Object.entries(record).sort(([a],[b])=>a.localeCompare(b,'en',{sensitivity:'variant'})));
  process.stdout.write(JSON.stringify(sorted)+'\n');
}
