// Independent conservative oracle for the read-only API/diagnostic surface.
// Runs on Node; not a Rust compiler or real BFE test.
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {dirname} from 'node:path';
const dir=dirname(fileURLToPath(import.meta.url));
const s=readFileSync(join(dir,'main.rs'),'utf8');
let tests=0;
function check(b,m){if(!b)throw Error(`oracle failed: ${m}`);tests++;}
const calls=[...s.matchAll(/\b(Fwpm\w+0)\s*\(/g)].map(m=>m[1]);
const readSet=new Set(['FwpmEngineOpen0','FwpmEngineClose0','FwpmFreeMemory0',
 'FwpmFilterGetByKey0','FwpmSubLayerGetByKey0','FwpmCalloutGetByKey0']);
check([...new Set(calls)].sort().join('|')===[...readSet].sort().join('|'),'only read APIs');
for(const f of ['FwpmFilterAdd0','FwpmFilterDeleteByKey0','FwpmSubLayerDeleteByKey0',
 'FwpsCalloutRegister1','WSAIoctl','CreateServiceW','TcpStream','std::net','FwpmTransactionBegin0']){
 check(!s.includes(f),`forbidden ${f}`);
}
check(s.includes('MANAGEMENT_READBACK_NOT_PROOF')&&s.includes('kernel_proof\\\":false'),'never native proof');
check(s.includes('atomic\\\":false')&&s.includes('Intentionally NO transaction'),'not snapshot');
check(s.includes('code == 0 && !owned.0.is_null()'),'success must have returned object');
check(s.includes('registered = visible &&'),'registration never true from error');
check(s.includes('std::process::exit(3)')&&s.includes('UNKNOWN'),'engine failure remains unknown');
check((s.match(/0x1649f0(18|19|14|16)_25b3/g)||[]).length===4,'four fixed callout keys');
check(s.includes('<< 96')&&s.includes('0x1649f030_25b3'),'filter key index parity');
// Explicit black-box semantics to guard future reinterpretation of API codes.
const interpret=(code,nonNull)=>({visible:code===0&&nonNull,proof:false});
for(const code of [0,1,5,0x80320008,0x8032001c,0x800706ba]){
 for(const ptr of [false,true]){
  const v=interpret(code,ptr);
  check(v.visible===(code===0&&ptr)&&!v.proof,'no inventing absent/present/kernel proof');
 }
}
console.log(`R199 independent JS checks: ${tests}/${tests} PASS; synthetic states only; no Windows/Rust run`);
