// Independently enumerated R56 negative model; no Windows API/driver/network calls.
const result={states:0,strict:0,weak:0,weakExcess:0,mutants:0,raceOrders:0,staleTraces:[]};
for(const family of [4,6])for(const reason of ['completion','policy'])for(let mask=0;mask<65536;mask++){
  result.states++;
  const all=(mask===65535),flow=(mask&2)!==0;
  if(all)result.strict++;
  if(flow)result.weak++;
  if(flow&&!all)result.weakExcess++;
}
for(let b=0;b<16;b++){
  const witness=65535^(1<<b);
  if(witness!==65535&&(witness|(1<<b))===65535)result.mutants++;
}
function enumerate(path,remain){
  if(!remain.length){
    let r=path.indexOf('R'),c=path.indexOf('C'),t=path.indexOf('T'),d=path.indexOf('D');
    if(r>d)return;
    result.raceOrders++;
    if(r<c&&c<d&&c<t)result.staleTraces.push(path);
    return;
  }
  for(let i=0;i<remain.length;i++)enumerate(path+remain[i],remain.slice(0,i)+remain.slice(i+1));
}
enumerate('','RCTD');
if(result.states!==262144||result.strict!==4||result.weak!==131072||
   result.weakExcess!==131068||result.mutants!==16||result.raceOrders!==12||
   result.staleTraces.join(',')!=='RCTD,RCDT')throw Error('R56 independent oracle failure');
console.log(JSON.stringify(result,null,2));
