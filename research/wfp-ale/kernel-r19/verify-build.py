"""Offline PE audit; imports inspected by pefile, never loads the driver."""
import hashlib,json,os,sys
from pathlib import Path
import pefile
p=Path(sys.argv[1]);raw=p.read_bytes();pe=pefile.PE(data=raw)
assert pe.FILE_HEADER.Machine==0x8664,'not x64'
assert pe.OPTIONAL_HEADER.Subsystem==1,'not native'
assert pe.OPTIONAL_HEADER.DllCharacteristics & 0x80,'FORCE_INTEGRITY absent'
assert pe.OPTIONAL_HEADER.DllCharacteristics & 0x100,'NX_COMPAT absent'
imports={}
for d in pe.DIRECTORY_ENTRY_IMPORT:
 imports[d.dll.decode().lower()]=[x.name.decode() for x in d.imports if x.name]
all_imports={v for values in imports.values() for v in values}
for required in ['PsSetCreateProcessNotifyRoutineEx','PsGetProcessCreateTimeQuadPart','PsGetProcessStartKey','FwpsCalloutRegister1','FwpsCalloutUnregisterById0']:
 assert required in all_imports,'missing '+required
assert not any(d in imports for d in ('kernel32.dll','user32.dll','ws2_32.dll','fwpuclnt.dll')),'user-mode dependency in kernel'
result=dict(ok=True,evidence='kernel_binary_build_and_static_import_audit_only',source_sha=os.environ['GITHUB_SHA'],driver_sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw),x64_native_pe=True,force_integrity=True,imports=imports,kernel_driver_loaded=False,wfp_filters_installed=False,process_birth_and_ale_native_observed=False,signature_acceptance=False,g2_pass=False,release_accepted=False)
Path(sys.argv[2]).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='imports'}))
