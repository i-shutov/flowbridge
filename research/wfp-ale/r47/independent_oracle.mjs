// R47 stand-alone *synthetic* independent oracle: no WFP, network, or driver API.
const modes = {recheck:'IVPAKB',generation:'IPAKB',serialized:'TAKB'};
function traces(mode) {
  const chain=modes[mode], all=[...(chain+'XNUL')].sort();
  const require=Object.fromEntries(all.map(e=>[e,new Set()]));
  for(let k=1;k<chain.length;k++) require[chain[k]].add(chain[k-1]);
  require.N.add('X');require.U.add('X');
  const out=[];
  function walk(prefix,done) {
    if(done.size===all.length){out.push(prefix);return;}
    for(const e of all) if(!done.has(e)&&[...require[e]].every(d=>done.has(d)))
      walk(prefix+e,new Set([...done,e]));
  }
  walk('',new Set());
  return out;
}
function simulate(strategy,events) {
  let physical=true,notified=false,currentEpoch=1,gen=1;
  let issued=false,checked=false,published=false,attested=false,claimed=false,loss=false,issueGen=0;
  const seen=new Set();
  const eligible=()=>!notified&&currentEpoch===1;
  const valid=()=>issued&&eligible()&&(strategy!=='generation'||issueGen===gen);
  function issue(){if(!issued&&eligible()){issued=true;issueGen=gen;}}
  function publish(){
    published=true;
    if(!physical)seen.add('publish_after_physical_exit');
    if(notified)seen.add('publish_after_exit_callback');
  }
  for(const e of events){
    switch(e){
      case 'X':physical=false;break;
      case 'N':notified=true;gen++;break;
      case 'U':currentEpoch=2;break;
      case 'L':loss=true;break;
      case 'I':issue();break;
      case 'V':if(issued&&eligible())checked=true;break;
      case 'P':if(issued&&(strategy!=='recheck'||checked))publish();break;
      case 'T':if(eligible()){issue();publish();}break;
      case 'A':if(published&&valid())attested=true;break;
      case 'K':if(attested&&valid()&&!loss)claimed=true;break;
      case 'B':if(claimed&&!loss){
        if(!physical)seen.add('copy_after_physical_exit');
        if(notified)seen.add('copy_after_callback');
      }break;
      default:throw Error('unexpected event '+e);
    }
  }
  return seen;
}
const output={scope:'synthetic, no native Windows proof',families:{}};
for(const family of [4,6]){
  output.families[family]={};
  for(const mode of Object.keys(modes)){
    const events=traces(mode),totals={},witness={};
    for(const trace of events)for(const outcome of simulate(mode,trace)){
      totals[outcome]=(totals[outcome]||0)+1;
      if(!witness[outcome])witness[outcome]=[...trace].join(' ');
    }
    const sort=o=>Object.fromEntries(Object.entries(o).sort((a,b)=>a[0].localeCompare(b[0])));
    output.families[family][mode]={schedules:events.length,observations:sort(totals),witness:sort(witness)};
  }
}
process.stdout.write(JSON.stringify(output,null,2)+'\n');
