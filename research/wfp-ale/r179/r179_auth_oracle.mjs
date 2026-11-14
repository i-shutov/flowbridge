// R179 independent oracle: synthetic policy only; no sockets, no WFP APIs.
let count=0, blocked=0, outside=0, admitted=0, physical=0;
for(const family of [4,6])
 for(const leg of ['accepted_redirect','physical_ssh','sibling_direct'])
  for(const original of ['selected','broker'])
   for(const current of ['selected','broker'])
    for(const flags of ['none','redirect','proxy','both'])
     for(const target of [false,true]) {
       let result='BLOCK';
       if(original==='broker') result='OUTSIDE_FILTER';
       else {
         const loopback=(leg==='accepted_redirect');
         const redirected=(flags==='redirect'||flags==='both');
         const processSelected=(leg!=='physical_ssh');
         const ticket=(leg==='accepted_redirect');
         if(loopback&&redirected&&target&&processSelected&&ticket) result='PERMIT_MODEL_ONLY';
       }
       count++;
       if(result==='BLOCK')blocked++;
       if(result==='OUTSIDE_FILTER')outside++;
       if(result==='PERMIT_MODEL_ONLY')admitted++;
       if(leg==='physical_ssh'&&original==='selected'&&result==='BLOCK')physical++;
       const row={family,leg,original,current,flags,target,result};
       const ordered={};for(const k of Object.keys(row).sort())ordered[k]=row[k];
       console.log(JSON.stringify(ordered));
     }
if(count!==192||blocked!==88||outside!==96||admitted!==8||physical!==32)throw Error('oracle mismatch');
