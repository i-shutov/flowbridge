/* R89 independent Node oracle; no network, WFP, driver, filesystem or subprocess. */
import {createHash} from 'node:crypto';
import {isIP} from 'node:net';

const cases = [
  ['v4_loopback','127.0.0.1',true,'local'],
  ['v4_loopback_other','127.0.0.2',true,'local'],
  ['v4_linklocal','169.254.4.5',true,'local'],
  ['v4_private_10','10.2.3.4',true,'private'],
  ['v4_private_172','172.16.10.5',true,'private'],
  ['v4_private_192','192.168.1.2',true,'private'],
  ['v4_shared','100.64.10.20',true,'non_global'],
  ['v4_documentation','192.0.2.3',true,'non_global'],
  ['v4_global','8.8.8.8',true,'global'],
  ['v4_unspecified','0.0.0.0',false,'invalid'],
  ['v4_multicast','239.1.1.1',false,'invalid'],
  ['v4_class_e','240.1.2.3',false,'invalid'],
  ['v6_loopback','::1',true,'local'],
  ['v6_ula','fd12::2',true,'private'],
  ['v6_documentation','2001:db8::2',true,'non_global'],
  ['v6_global','2606:4700:4700::1111',true,'global'],
  ['v6_linklocal','fe80::4',false,'invalid'],
  ['v6_unspecified','::',false,'invalid'],
  ['v6_multicast','ff02::1',false,'invalid'],
  ['v6_mapped','::ffff:127.0.0.1',false,'invalid']
];
function bytes4(value) {return value.split('.').map(x => Number(x));}
function bytes6(value) {
  const last = value.lastIndexOf(':');
  if (value.includes('.')) {
    const b = bytes4(value.slice(last+1));
    value = value.slice(0,last+1) + ((b[0]*256+b[1]).toString(16)) + ':' + ((b[2]*256+b[3]).toString(16));
  }
  const pos = value.indexOf('::');
  let pieces;
  if (pos >= 0) {
    const before = value.slice(0,pos).split(':').filter(Boolean);
    const after = value.slice(pos+2).split(':').filter(Boolean);
    pieces = [...before,...Array(8 - before.length - after.length).fill('0'),...after];
  } else {pieces=value.split(':');}
  if(pieces.length!==8)throw Error('invalid IPv6 '+value);
  return pieces.flatMap(x=>[parseInt(x,16) >> 8,parseInt(x,16)&255]);
}
function valid(address) {
  const family = isIP(address);
  if(family!==4 && family!==6)throw Error('invalid case address '+address);
  const b = family===4 ? bytes4(address) : bytes6(address);
  if (family===4)return b.some(x=>x!==0) && b[0]<224;
  if (b.every(x=>x===0) || b[0]===255)return false;
  if(b[0]===254 && (b[1]&192)===128)return false;
  return !(b.slice(0,10).every(x=>x===0)&&b[10]===255&&b[11]===255);
}
function decision(address, port) {
  if(!valid(address))return 'DEST_REJECTED';
  if((address==='127.0.0.1'||address==='::1') && port===4040) return 'BROKER_PORT_EXCLUDED';
  return 'SSH_REMOTE_NAMESPACE_CANDIDATE';
}
let raw='';let count=0;const histogram={};
for(const [id,ip,expected,scope] of cases){
  if(valid(ip)!==expected)throw Error('golden validity mismatch '+id);
  for(const port of [4040,8080]) {
    const verdict=decision(ip,port); count++;
    raw += [id,ip,scope,port,verdict].join("|")+"\n";
    histogram[verdict]=(histogram[verdict]||0)+1;
  }
}
if(count!==40||histogram.SSH_REMOTE_NAMESPACE_CANDIDATE!==24||histogram.BROKER_PORT_EXCLUDED!==2||histogram.DEST_REJECTED!==14)throw Error('counts');
if(decision('127.0.0.2',4040)!=='SSH_REMOTE_NAMESPACE_CANDIDATE')throw Error('127/8 gap');
if(decision('169.254.4.5',8080)!=='SSH_REMOTE_NAMESPACE_CANDIDATE'||decision('fe80::4',8080)!=='DEST_REJECTED')throw Error('linklocal asymmetry');
console.log('R89_NODE_PASS '+count+' cases');
console.log('R89_SHA256='+createHash('sha256').update(raw).digest('hex'));
console.log(JSON.stringify(histogram));
