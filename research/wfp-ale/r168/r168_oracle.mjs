// Independent R168 oracle, no imports, driver, network or WFP access.
function verdict(duration, eof, activity, heartbeat, count) {
  let state;
  if (heartbeat === false) state='KERNEL_LOSS';
  else if (eof !== null && eof < 60 && eof <= duration) state='CLEAN_EOF';
  else if (duration > 60) state='COPY_TIMEOUT';
  else state='COPY_PENDING';
  let failure=state==='KERNEL_LOSS'||state==='COPY_TIMEOUT';
  return {outcome:state,revoke:failure,sibling_canceled:failure?count-1:0,stop_expected:failure};
}
let rows=[];
for (const horizon of [5,30,59,61,75,120])
for (const eof_at of [null,2,10,40,90])
for (const activity of ['idle','streaming'])
for (const ping of [false,true])
for (const workers of [1,2,3])
  rows.push({horizon,eof_at,activity,ping,workers,result:verdict(horizon,eof_at,activity,ping,workers)});
if(rows.length!==360)throw Error('matrix cardinality');
if(verdict(75,null,'streaming',true,3).sibling_canceled!==2)throw Error('sibling case');
if(verdict(120,40,'idle',true,2).stop_expected)throw Error('clean EOF');
process.stdout.write(JSON.stringify(rows)+'\n');
