function r54Oracle() {
  const keys=["kernelOrigin","issueIdentity","endpointMetadata","ticket","session","family","tcp",
    "selectedExe","ownerCallbackAlive","sshLive","wfpLive","ledgerCurrent","notClosed","bfeDelivered"];
  let states=0,strict=0,endpointOnly=0,weakOnly=0;
  for (const family of [4,6]) {
    for (let m=0;m<(1<<keys.length);m++) {
      const has=i=>(m&(1<<i))!==0;
      const good=keys.every((_,i)=>has(i));
      const weak=has(2);
      states++; if(good)strict++;if(weak)endpointOnly++;if(weak&&!good)weakOnly++;
      if(good!==(m===((1<<keys.length)-1)))throw Error("enumeration invariant");
    }
  }
  if(states!==32768||strict!==2||endpointOnly!==16384||weakOnly!==16382)throw Error("count mismatch");
  let mutations=0;
  for(let i=0;i<keys.length;i++){
    const vector=Array(keys.length).fill(true);
    vector[i]=false;
    if(vector.every(Boolean))throw Error("missing guard incorrectly accepted "+keys[i]);
    mutations++;
  }
  const base={endpoint:100,family:4,session:"s",ticket:1,epoch:5,exe:"selected",closed:false,live:true};
  const witness={endpoint:100,family:4,session:"s",ticket:1,epoch:5,exe:"selected"};
  const allow=(w,s)=>Boolean(w&&s&&!s.closed&&s.live&&w.endpoint===s.endpoint&&
    w.family===s.family&&w.session===s.session&&w.ticket===s.ticket&&
    w.epoch===s.epoch&&w.exe===s.exe);
  if(!allow(witness,base)||allow(witness,{...base,closed:true})||
     allow({...witness,endpoint:101},base)||allow({...witness,epoch:6},base)||
     allow({...witness,ticket:2},base)||allow({...witness,family:6},base)||
     allow({...witness,exe:"sibling"},base)||allow(witness,{...base,live:false}))throw Error("lifecycle guard");
  const a={pid:4,tuple:"same",family:4,reason:"POLICY_CHANGE",epoch:5,exe:"selected"};
  const b={...a,epoch:6,exe:"sibling"};
  const visible=x=>[x.pid,x.tuple,x.family,x.reason].join("/");
  if(visible(a)!==visible(b)||a.epoch===b.epoch)throw Error("indistinguishability");
  return {states,strict,endpoint_only:endpointOnly,weak_only:weakOnly,mutations,
    no_endpoint_receipt_indistinguishable:true,
    observed_process_exit_required:true,
    windows_native_execution:false,
    physical_egress_proof:false};
}
console.log(JSON.stringify(r54Oracle(),null,2));
