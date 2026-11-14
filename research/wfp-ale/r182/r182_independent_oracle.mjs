// R182 independent negative oracle: separate boolean-fact projection, no Python imports.
// The trusted per-flow binding is hypothetical and is NOT supplied by current WFP code.
const family = [4,6], phases=['initial','honor','reauth'];
const causes=['policy','interface','ipsec','classify_completion'];
const directions=['out','in'], tokens=['trusted','missing','forged','stale'];
const metas=['full','fwp_empty'];
const worlds=['selected','sibling_direct','proxy_ssh','pid_reused','endpoint_reused','tuple_reused',
'foreign_compartment','owner_dead','bfe_lost','ssh_lost','revoked','witness_unacked',
'claim_absent','not_established','udp_dns'];
const stable=(v)=>JSON.stringify(Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])));
for(const f of family)for(const phase of phases)for(const cause of causes)for(const direction of directions)
for(const token of tokens)for(const metadata of metas)for(const world of worlds){
  const oneShotSettled=!['witness_unacked','claim_absent','not_established'].includes(world);
  const ownerLive=world!=='owner_dead';
  const epochsIntact=!['pid_reused','endpoint_reused','tuple_reused','foreign_compartment',
      'bfe_lost','ssh_lost'].includes(world);
  const isOriginal=world!=='sibling_direct';
  const originalTCP=world!=='udp_dns';
  const canAuthorize=(phase==='reauth' && token==='trusted' && world==='selected' &&
    oneShotSettled && ownerLive && epochsIntact && originalTCP);
  const unsafe=(phase==='reauth' && isOriginal);
  const row={family:f,phase,cause,direction,token,metadata,world,
    strict:Number(canAuthorize),unsafe:Number(unsafe),false_allow:Number(unsafe&&!canAuthorize)};
  process.stdout.write(stable(row)+'\n');
}
