// R65 independent Node source-level fail-closed audit; no network or OS calls.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const self = fileURLToPath(import.meta.url);
const source = process.argv[2] ?? resolve(self, '../../r63/r63_endpoint_probe.rs');
const src = readFileSync(source, 'utf8');
const checks = {
  fixedOpcode: /ALE_ENDPOINT_IOCTL_OPCODE:\s*u32\s*=\s*0x4000_0000\s*\|\s*0x1800_0000\s*\|\s*205/.test(src),
  quarantinedGate: /ProbeReadiness::DisabledAllocatorOwnershipUnverified\s*\}/.test(src),
  safeStub: /fn\s+inspect_existing_socket\([\s\S]*?\)\s*->\s*Result<EndpointDiagnostic,\s*ProbeError>\s*\{\s*Err\(ProbeError::AllocatorOwnershipUnverified\)\s*\}/.test(src),
  noUnsafeBlock: !/\bunsafe\s*\{/.test(src),
  noUnsafeExtern: !/\bunsafe\s+extern/.test(src),
  noFfiImports: !/\bextern\s*"system"/.test(src),
  noLiveWsaioclt: !/\bWSAIoctl\s*\(/.test(src),
  noLiveEndpointQuery: !/\bFwpsAleEndpointGetById0\s*\(/.test(src),
  noLiveFrees: !/\b(?:FwpmFreeMemory0|FwpsFreeMemory0|CoTaskMemFree)\s*\(/.test(src),
  noLiveBfe: !/\bFwpmEngine(?:Open|Close)0\s*\(/.test(src),
  unobservedIsNotBlock: /!o\.dispatched\s*\{\s*return Assessment::Unobserved;/.test(src),
  diagnosticNotOrigin: /Assessment::EndpointOnlyNotOrigin\s*\n\}/.test(src)
};
const failures = Object.entries(checks).filter(([k,v])=>!v).map(([k])=>k);
const result = {schema:'r65-static-safety-v1',file:source,checks,passed:failures.length===0,failed:failures};
console.log(JSON.stringify(result,null,2));
if(failures.length) process.exitCode=1;
