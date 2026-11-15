#!/usr/bin/env node
// Independent source oracle; read-only, no native WFP, no driver or sockets.
import fs from 'node:fs';import path from 'node:path';
const root=process.argv[2]??path.resolve(import.meta.dirname,'../../../');
const dir=path.join(root,'research/wfp-ale/kernel-r19/kernel/src');
const names=['lib','ledger','handoff','auth_appid','action_rights','redirect'];
const src=Object.fromEntries(names.map(n=>[n,fs.readFileSync(path.join(dir,n+'.rs'),'utf8').split('#[cfg(test)]')[0]]));
const mods=[...src.lib.matchAll(/^mod\s+(\w+)\s*;/gm)].map(x=>x[1]).sort();
if(JSON.stringify(mods)!==JSON.stringify(names.filter(x=>x!=='lib').sort())||(src.lib.match(/include!\s*\(/g)||[]).length!==1)throw Error('UNKNOWN modules');
if(!src.ledger.includes('pub fn observe(')||!src.ledger.includes('self.queue[(self.read+self.count)%MAX_RECORDS]=w;self.count+=1'))throw Error('UNKNOWN producer');
if(!src.ledger.includes('pub fn pop(')||!src.lib.includes('(*STATE.0.get()).pop()')||!src.lib.includes('FB_WITNESS_IOCTL'))throw Error('UNKNOWN consumer');
const hits=[];for(const [name,body] of Object.entries(src)){body.split('\n').forEach((line,i)=>{if(/\.\s*observe\s*\(|\bLedger\s*::\s*observe\s*\(/.test(line))hits.push([name,i+1]);});}
console.log(JSON.stringify({calls:hits,verdict:hits.length?'REVIEW_NEW_PRODUCER':'NO_RUNTIME_WITNESS_PRODUCER'}));
