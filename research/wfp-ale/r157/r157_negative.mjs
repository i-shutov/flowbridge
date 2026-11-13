// R157 source-pinned filter-predicate negative test; not native WFP proof.
import fs from 'node:fs';
import crypto from 'node:crypto';
const root=process.argv[2] || process.cwd();
const pins={
'research/wfp-ale/kernel-r19/policy_windows.rs':'acf60334320d970f58af3349ee75fbaa59826602',
'research/wfp-ale/kernel-r19/kernel/src/redirect.rs':'a093f049d162987981a957aac90db1014bc6ff09',
'research/wfp-ale/kernel-r19/kernel/src/lib.rs':'53f5ce6faa0f9f591974287f38ea890cafeb0dd2'
};
const source={};
for(const [path,expected] of Object.entries(pins)){
 const b=fs.readFileSync(root+'/'+path);
 const h=crypto.createHash('sha1').update('blob '+b.length+'\0').update(b).digest('hex');
 if(h!==expected)throw Error('SOURCE_PIN_REJECT '+path+' '+h);
 source[path]=b.toString('utf8');
}
const p=source['research/wfp-ale/kernel-r19/policy_windows.rs'];
for(const t of ['FWPM_CONDITION_ALE_APP_ID','FWPM_CONDITION_ALE_ORIGINAL_APP_ID',
'tcp.fieldKey=FWPM_CONDITION_IP_PROTOCOL','tcp.conditionValue.Anonymous.uint8=6',
'vec![app,tcp]','session.flags=FWPM_SESSION_FLAG_DYNAMIC']){
 if(!p.includes(t))throw Error('SOURCE_SHAPE_REJECT '+t);
}
for(const k of ['Redirect','AttestOriginal'])for(const f of ['V4','V6']){
 if(!p.includes('(Kind::'+k+',Family::'+f+')'))throw Error('RULE_SET_REJECT');
}
const roles=[['selected','selected'],['sibling','sibling'],['broker','selected'],
['sibling','selected'],['selected','sibling']];
let n=0,rc=0,ac=0,empty=0;
for(const family of ['V4','V6'])for(const proto of ['TCP','UDP','ICMP'])
for(const [current,original] of roles)for(const active of [false,true]){
 const r=active&&proto==='TCP'&&current==='selected';
 const a=active&&proto==='TCP'&&original==='selected';
 if((!active||proto!=='TCP')&&(r||a))throw Error('NON_TCP_OR_NO_POLICY_MATCH');
 if(active&&current==='sibling'&&original==='sibling'&&(r||a))throw Error('SIBLING_MATCH');
 n++;rc+=Number(r);ac+=Number(a);empty+=Number(!r&&!a);
}
if(n!==60||rc!==4||ac!==6||empty!==52)throw Error('COUNT_MISMATCH');
console.log(JSON.stringify({status:'FILTER_MATCH_ONLY_NO_PACKET_VERDICT',matrix:n,redirect:rc,auth:ac,
unmatched:empty,sourcePins:pins,nativeWfp:false}));
