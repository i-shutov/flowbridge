// R45 independent event-log oracle; pure Node stdlib, no network/Windows/WFP.
// State-space analysis is independent from the Python class implementation.
import assert from 'node:assert/strict';

function apply(trace) {
  let armed = false, configured = false, dead = false;
  let armAccepted = 0, rearmAccepted = 0, formerArms = 0;
  for (const event of trace) {
    switch (event) {
      case 'ARM':
        if (!configured && !dead) {
          if (formerArms > 0) rearmAccepted++;
          armAccepted++;
          configured = armed = true;
        }
        formerArms++;
        break;
      case 'EXIT':
      case 'STOP':
      case 'LOSS':
        if (configured) { armed = false; dead = true; }
        break;
      case 'CLAIM':
        break; // Claims cannot re-arm or reset the kernel Book.
    }
  }
  return {armed, configured, dead, armAccepted, rearmAccepted};
}

// Independent *logical* safety oracle: if a successful ARM was followed by
// any broker EXIT, STOP or LOSS, then this driver instance can never re-ARM.
function contract(trace) {
  const firstArm = trace.indexOf('ARM');
  const after = firstArm >= 0 && trace.slice(firstArm + 1).some(x =>
    x === 'EXIT' || x === 'STOP' || x === 'LOSS');
  return !after || !apply(trace).armed;
}

let worlds=0, terminal=0, noRearm=0, violations=0;
const alphabet=['ARM','EXIT','STOP','LOSS','CLAIM'];
for (let n=1;n<=6;n++) {
  const total=alphabet.length ** n;
  for (let code=0;code<total;code++) {
    let x=code;const trace=[];
    for(let i=0;i<n;i++){trace.push(alphabet[x%alphabet.length]);x=Math.floor(x/alphabet.length);}
    const s=apply(trace);
    worlds++;
    if(s.dead)terminal++;
    if(s.dead && !s.armed && s.armAccepted===1 && s.rearmAccepted===0)noRearm++;
    if(!contract(trace) || s.rearmAccepted!==0 || s.armAccepted>1)violations++;
  }
}
assert.equal(worlds,19530);
assert.equal(violations,0);
assert.ok(terminal>0 && noRearm>0);
// Control: intentionally weakened transition (reARM when dead) violates the contract.
const weakened = (trace) => {let a=false,ever=false;
  for(const event of trace) {if(event==='ARM'){a=true;ever=true;}else if(event==='EXIT'||event==='STOP'||event==='LOSS')a=false;}
  return ever&&a;};
assert.equal(weakened(['ARM','EXIT','ARM']),true);
assert.equal(apply(['ARM','EXIT','ARM']).armed,false);
console.log(JSON.stringify({worlds,terminal,noRearm,violations,
   weakenedCounterexample:'ARM EXIT ARM',nativeWindowsExecuted:false,rustExecuted:false},null,2));
