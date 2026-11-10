/* Independent golden-data oracle. No socket or native call. No imports except crypto. */
import {createHash} from 'node:crypto';
const remotes = {
  v4: ['8.8.8.8','10.3.2.1'],
  v6: ['2606:4700:4700::1111','fd13::1']
};
const entries = [
 ['v4','unspecified','0.0.0.0',0,true],
 ['v4','broker_exact','127.0.0.1',0,true],
 ['v4','other_loopback','127.0.0.2',0,false],
 ['v4','bound_rfc1918_10','10.9.0.4',0,false],
 ['v4','bound_rfc1918_172','172.20.3.2',0,false],
 ['v4','bound_rfc1918_192','192.168.1.10',0,false],
 ['v4','bound_linklocal','169.254.6.8',0,false],
 ['v6','unspecified','::',0,true],
 ['v6','broker_exact','::1',0,true],
 ['v6','other_loopback','::2',0,false],
 ['v6','bound_ula','fd12::9',0,false],
 ['v6','bound_linklocal_scoped','fe80::4',4,false],
 ['v6','bound_global','2001:db8::10',0,false],
 ['v6','scoped_loopback','::1',4,false],
];
/* Independent analytical predicate: wildcard or exact loopback with v6 scope 0. */
function oracle(family, source, scope) {
  if(family==='v4')return source==='0.0.0.0'||source==='127.0.0.1';
  return scope===0&&(source==='::'||source==='::1');
}
let count=0, blocked=0, admitted=0, text='';
for(const [family,name,local,scope,expected] of entries) {
  const got=oracle(family,local,scope);
  if(got!==expected)throw Error('golden mismatch: '+name);
  for(const remote of remotes[family]) {
    const verdict=got?'LOCAL_SOURCE_ADMITTED_TO_LATER_GATES':'BLOCK_BEFORE_TICKET';
    text+=[family,name,local,scope,remote,verdict].join('|')+'\n';
    count++;if(got)admitted++;else blocked++;
  }
}
if(count!==28||blocked!==20||admitted!==8)throw Error('histogram mismatch');
console.log('R90_NODE_ROWS='+count+' BLOCKED='+blocked+' ADMITTED='+admitted);
console.log('R90_SHA256='+createHash('sha256').update(text,'utf8').digest('hex'));
