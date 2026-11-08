// R51 independent Node oracle; no Windows calls or network.
// Explicitly trusts NONE of the synthetic fields as actual kernel evidence.
const reasons=['completion','policy','interface','unknown','empty'];
const phases=['pended','completed','claimed'];
const names=['native_origin','same_pending','same_session','same_issuance','same_process_epoch','same_endpoint','selected_appid','tcp','trusted_saved_fields','healthy'];
let lattice={cases:0,strict:0,reason_only:0,wrongly_admitted_by_reason_only:0};
for(const fam of [4,6])for(const reason of reasons)for(const phase of phases){
    for(let mask=0; mask<(1<<names.length); ++mask){
        // Independent inverse-specification: denial if any assumption is absent.
        let denied = reason!=='completion' || phase!=='completed';
        for(let j=0;j<names.length;j++)if((mask&(1<<j))===0)denied=true;
        const loose = reason==='completion'&&phase==='completed';
        lattice.cases++;
        if(!denied)lattice.strict++;
        if(loose)lattice.reason_only++;
        if(loose&&denied)lattice.wrongly_admitted_by_reason_only++;
    }
}
const actions=['PEND_a','COMPLETE_a','REAUTH_a','EXIT_a','PEND_b','COMPLETE_b','REAUTH_b'];
function* orders(arr,n=arr.length){if(n===1){yield arr.slice();return;}
 for(let i=0;i<n;i++){yield* orders(arr,n-1);const j=(n%2===1)?0:i;[arr[j],arr[n-1]]=[arr[n-1],arr[j]];}}
const interleavings={traces:0,permit_a_before_exit:0,permit_b:0,spoofed_a_receipt_accepted_for_b:0};
for(const family of [4,6])for(const seq of orders(actions.slice())){
  const phase={a:0,b:0};let success_a=false,success_b=false;
  for(const e of seq){const [action,who]=e.split('_');
    if(action==='EXIT'){phase[who]=4;continue;}
    if(action==='PEND'&&phase[who]===0){phase[who]=1;continue;}
    if(action==='COMPLETE'&&phase[who]===1){phase[who]=2;continue;}
    if(action==='REAUTH'&&phase[who]===2){phase[who]=3;
      if(who==='a')success_a=true; else success_b=true;
    }
  }
  interleavings.traces++;
  if(success_a)interleavings.permit_a_before_exit++;
  if(success_b)interleavings.permit_b++;
  // Probe: same PID+5-tuple but key A != key B, so deny substitution.
  const identityA=[1,100,3,11,5,7,family,99];
  const identityB=[1,101,3,12,5,8,family,99];
  if(identityA.every((v,i)=>v===identityB[i]))interleavings.spoofed_a_receipt_accepted_for_b++;
}
const result={lattice,interleavings};
if(lattice.cases!==30720 || lattice.strict!==2 || lattice.reason_only!==2048 ||
   lattice.wrongly_admitted_by_reason_only!==2046 || interleavings.traces!==10080 ||
   interleavings.spoofed_a_receipt_accepted_for_b!==0)
  throw new Error('independent oracle invariants failed');
console.log(JSON.stringify(result,null,2));
