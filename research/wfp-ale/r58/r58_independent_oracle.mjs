// R58 independent JS oracle: logic from explicit witness obligations, not Python imports.
// Synthetic Boolean lattice. No operating system, drivers, sockets, or files read.
const report={states:0,unobserved:0,model_permit:0,rejected:0,
 reason_dispatch_only_permit:0,reason_dispatch_false_permit:0,missing_join_permit:0,
 indistinguishable_pairs:0,swapped_order_pairs:0};
for(const family of ['IPv4','IPv6']){
 for(const order of ['A-then-B','B-then-A']){
  // Both tickets can generate the same reason, tuple, and family when the
  // hypothetical joined identity is missing. Swapping their arrival order
  // cannot be used as an authenticated attribution rule.
  report.indistinguishable_pairs++;
  report.swapped_order_pairs++;
  for(const actor of ['selected','sibling']){
   for(let bits=0;bits<4096;bits++){
    const enabled = p => (bits & (2**p))!==0;
    const dispatched=enabled(0);
    const completion=enabled(1);
    // A genuine original-process receipt would have to satisfy every guard,
    // and the sibling is never a selected-process permit under that policy.
    const allWitnessed=bits===4095 && actor==='selected';
    const strict=dispatched && allWitnessed;
    const reasonOnly=dispatched && completion;
    const missingJoin=dispatched && completion && enabled(2) && enabled(10) && enabled(11);
    report.states++;
    report.unobserved+=!dispatched ? 1 : 0;
    report.model_permit+=strict ? 1 : 0;
    report.rejected+=dispatched && !strict ? 1 : 0;
    report.reason_dispatch_only_permit+=reasonOnly ? 1 : 0;
    report.reason_dispatch_false_permit+=reasonOnly && !strict ? 1 : 0;
    report.missing_join_permit+=missingJoin ? 1 : 0;
   }
  }
 }
}
if(report.states!==32768 || report.model_permit!==4 || report.reason_dispatch_false_permit!==8188)
  throw new Error('independent oracle invariant failed');
console.log(JSON.stringify(report,null,2));
