#!/usr/bin/env node
// R61 independent combinatorial oracle; no sockets/driver/network; copied
// redirect-record acceptance in a different socket is hypothetical, NOT proven.
import {createHash} from 'node:crypto';
const keys=['family','accepted','context','records','record_family','outbound',
            'auth','pending','query_ok','set_ok','ssh','wfp','epoch_ok','death'];
const domains=[[4,6],['A','B'],['A','B'],['A','B'],[4,6],['A','B'],
               [0,1],[0,1],[0,1],[0,1],[0,1],[0,1],[0,1],[0,1,2]];
const labels=['paired','paired_after_physical_exit_before_callback','strict','weak',
              'weak_aborted_pend','weak_after_observed_death','weak_after_observed_loss',
              'weak_wrong_accept','weak_wrong_family','weak_wrong_outbound','weak_wrong_records'];
const counts=Object.fromEntries(labels.map(k=>[k,0]));
const sha=createHash('sha256');let states=0;
function classify(a){
  const [ip,s,c,r,rf,o,auth,pend,q,so,ssh,wfp,epoch,death]=a;
  const admitted=Boolean(c==='A' && auth===1 && epoch===1 && ssh===1 && wfp===1 && death!==2);
  const weak=Boolean(admitted && q && so);
  const paired=Boolean(weak && s===c && c===r && o===s && rf===ip && pend===1);
  const strict=Boolean(paired && death===0);
  return {
    paired,paired_after_physical_exit_before_callback:paired && death===1,
    strict,weak,weak_aborted_pend:weak && !pend,
    weak_after_observed_death:weak && death===2,
    weak_after_observed_loss:weak && (!ssh || !wfp),
    weak_wrong_accept:weak && s!==c,
    weak_wrong_family:weak && rf!==ip,
    weak_wrong_outbound:weak && o!==c,
    weak_wrong_records:weak && r!==c,
  };
}
function visit(depth,row){
  if(depth!==domains.length){for(const v of domains[depth])visit(depth+1,[...row,v]);return;}
  const outcome=classify(row);
  const bits=labels.map(k=>outcome[k]?'1':'0').join('');
  sha.update(row.join(',')+'|'+bits+'\n');
  for(const k of labels)if(outcome[k])counts[k]++;
  states++;
}
visit(0,[]);
if(states!==24576 || !(counts.weak>counts.paired && counts.paired>counts.strict))
  throw Error('R61 cardinality or inequality invariant violated');
if(counts.weak_after_observed_loss!==0 || counts.weak_after_observed_death!==0)
  throw Error('Observed terminal loss was allowed');
const ledger=new Map([['T_A','issued']]);
const firstClaim=ledger.delete('T_A');
const secondClaim=ledger.delete('T_A');
const result={model:'R61 conditional redirect record / context handoff, not Windows proof',
 states,counts,stream_sha256:sha.digest('hex'),
 replay:{first_claim:firstClaim,second_claim:secondClaim,record_set_replay_specified_as_forbidden_by_docs:false},
 notes:'Record transfer/replay OS acceptance is intentionally not asserted.'};
console.log(JSON.stringify(result,null,2));
