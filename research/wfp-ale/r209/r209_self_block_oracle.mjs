// R209 independent event/constraint oracle, no Windows, network or driver access.
import assert from 'node:assert/strict';
const chosen='C:/selected-original.exe', service='C:/flowbridge-broker.exe';
const ports={4:19094,6:19096};
let count=0;
function check(name,fn){fn();count++;console.log('PASS '+name);}
function matchPolicy(flow){return flow.proto===6 && flow.original===chosen;}
function driver(flow){
  // R19 first checks redirected metadata; next requires the exact broker
  // loopback address, selected-process provenance, ticket, and listening port.
  const loopback=flow.family===4?'127.0.0.1':'::1';
  return flow.redirected && flow.remote===loopback && flow.port===ports[flow.family]
      && flow.owner===chosen && flow.ticket===true;
}
function outcome(flow){return !matchPolicy(flow)?'NOT_MATCHED':driver(flow)?'ATTEST':'BLOCK';}
function start(family){return {proto:6,family,owner:chosen,original:chosen,current:chosen,
  remote:family===4?'127.0.0.1':'::1',port:ports[family],redirected:true,ticket:true};}
function ssh(family,endpoint='198.51.100.44'){
  const p={proto:6,family,owner:service,original:chosen,current:service,
    remote:endpoint,port:22,redirected:true,ticket:false};
  return p;
}
check('v4 original admitted',()=>assert.equal(outcome(start(4)),'ATTEST'));
check('v6 original admitted',()=>assert.equal(outcome(start(6)),'ATTEST'));
check('v4 tagged physical SSH blocked',()=>assert.equal(outcome(ssh(4)),'BLOCK'));
check('v6 tagged physical SSH blocked',()=>assert.equal(outcome(ssh(6)),'BLOCK'));
check('physical SSH remains blocked if local IP',()=>assert.equal(outcome(ssh(4,'127.0.0.1')),'BLOCK'));
check('direct selected sibling blocked',()=>assert.equal(outcome({...start(4),remote:'203.0.113.3',redirected:false,ticket:false}),'BLOCK'));
check('stripped records no longer match selected ORIGINAL_APP_ID',()=>assert.equal(outcome({...ssh(4),original:service}),'NOT_MATCHED'));
check('UDP DNS no selected TCP filter match',()=>assert.equal(outcome({...start(4),proto:17,remote:'8.8.8.8',port:53}),'NOT_MATCHED'));
check('broker port spoof does not establish selected identity',()=>assert.equal(outcome({...ssh(4,'127.0.0.1'),port:ports[4]}),'BLOCK'));
console.log(String(count)+'/'+String(count)+' PASS (symbolic negative tests, not Windows proof)');
