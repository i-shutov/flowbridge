#!/usr/bin/env node
// Independent R206 real POSIX symlink oracle; not native Windows or WFP.
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import assert from 'node:assert/strict';
const outside=(r,t)=>{const rel=path.relative(path.resolve(r),path.resolve(t));return rel==='..'||rel.startsWith('..'+path.sep)||path.isAbsolute(rel)};
const safe=(r,t)=>{if(!outside(r,t))return false;for(const x of [r,t]){let p=path.resolve(x);while(true){if(fs.existsSync(p)&&fs.lstatSync(p).isSymbolicLink())return false;const q=path.dirname(p);if(q===p)break;p=q;}}return true;};
const b=fs.mkdtempSync(path.join(os.tmpdir(),'r206-'));
try{
const r=path.join(b,'repo');fs.mkdirSync(r);const inside=path.join(r,'empty');fs.mkdirSync(inside);
assert.ok(outside(r,path.join(b,'elsewhere'))&&safe(r,path.join(b,'elsewhere')));
assert.ok(!outside(r,inside)&&!safe(r,inside));
const leaf=path.join(b,'leaf'),parent=path.join(b,'parent'),alias=path.join(b,'alias');
fs.symlinkSync(inside,leaf,'dir');fs.symlinkSync(r,parent,'dir');fs.symlinkSync(r,alias,'dir');
for(const [base,target] of [[r,leaf],[r,path.join(parent,'empty')],[alias,inside]]){
 assert.ok(outside(base,target)&&!safe(base,target));assert.equal(fs.realpathSync(target),inside);
}
console.log('R206-JS: 5/5 PASS, real POSIX symlink counterexamples; NOT Windows');
}finally{fs.rmSync(b,{recursive:true,force:true})}
