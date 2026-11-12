// Independent bit-state reference. No imports from Python or Rust.
import {createHash} from 'node:crypto';
const OWNER=1,TICKET=2,AUTH=4,LL=8,BL=16,EXPIRED=32;
// Enumerate six-digit base-6 words, not recursive permutation generation.
const permutations=[];
for(let n=0;n<46656;n++) {
  const d=[0,0,0,0,0,0];let q=n;
  for(let i=5;i>=0;i--){d[i]=q%6;q=Math.floor(q/6);}
  if(new Set(d).size===6)permutations.push(d);
}
if(permutations.length!==720)throw Error('permutation count');
function run(h,v,order){
  let s=OWNER|TICKET;const columns=['','','',''];
  for(const e of order){
    let result=false;
    if(e<4){
      if(s&(LL|BL)){s=(s|BL)&~TICKET;}
      else if(e<2){
        if((s&(OWNER|TICKET|AUTH|EXPIRED))===(OWNER|TICKET)){s|=AUTH;result=true;}
      }else{
        const payload=e===2?v:0;
        if(payload!==2 && payload!==3 && (s&TICKET)){
          s&=~TICKET;
          result=payload===0 && (s&(AUTH|OWNER|EXPIRED))===(AUTH|OWNER);
        }
      }
    }else if(e===5){s|=EXPIRED;result=true;}
    else {
      switch(h){
        case 0:break;
        case 1:s&=~OWNER;result=true;break;
        case 2:s=(s&~OWNER)|LL;break;
        case 3:s=(s|BL)&~TICKET;result=true;break;
        case 4:if(!(s&BL)){if(s&EXPIRED)s&=~TICKET;s|=BL;}break;
        default:throw Error('hazard');
      }
    }
    columns[0]+=result?'1':'0';columns[1]+=(s&BL)?'1':'0';
    columns[2]+=(s&LL)?'1':'0';columns[3]+=(s&OWNER)&&!(s&LL)?'1':'0';
  }return columns;
}
let traces=0,claims=0,auths=0;const counts={'0':0,'1':0,'2':0,'3':0,'4':0};const hash=createHash('sha256');
for(const family of [4,6])for(let h=0;h<5;h++)for(let v=0;v<5;v++)for(const order of permutations){
  const columns=run(h,v,order);let taken=0;
  for(let i=0;i<6;i++)if(columns[0][i]==='1'){
    if(order[i]===2||order[i]===3){taken++;claims++;counts[h]++;}
    if(order[i]===0||order[i]===1)auths++;
  }
  if(taken>1)throw Error('one-use violated');
  hash.update(`${family}|${h}|${v}|${order.join('')}|${columns.join('|')}\n`,'ascii');traces++;
}
console.log(JSON.stringify({traces,events:traces*6,accepted_claims:claims,accepted_auths:auths,
  claims_by_hazard:counts,sha256:hash.digest('hex')}));
