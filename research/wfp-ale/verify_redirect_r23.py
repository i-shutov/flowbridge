#!/usr/bin/env python3
"""Independent stdlib PE/archive audit. No binary, driver or native API is executed.
The pinned experiment proves components, not a loaded-driver end-to-end redirect.
"""
from pathlib import Path
import argparse, hashlib, io, json, struct, zipfile
SOURCE='eb1e7561fd14ff05d1d899b7ca43e46988b883c7'
RUN=42398383944
PINS={
 'kernel':'2e81dc9908ca69d42ee2c3a004a68f49ff5286478b1882512fbcaaa1827faed7',
 'ssh':'38d930eb30d47f910c20daf4785ab48cd454d0b22f2f97b459bc0cdca9432963',
 'socket':'35aee98cfa8d982dc962b5eac27a42eb913e0d2ea2e01e33e1fb26db7d3db138',
}
DRIVER='94eb29c5c6c016bb52f387c1b2b3703bc8f8a12681b83e84e8df693e5cdbcc31'
BROKER='c61bba5d6b6cd4c378454f1e4e39cd963d18a811a07a0b75687199befcf104ee'
REQUIRED={'PsSetCreateProcessNotifyRoutineEx','PsGetProcessStartKey','PsGetProcessCreateTimeQuadPart',
 'IoGetRequestorProcess','FwpsAcquireClassifyHandle0','FwpsAcquireWritableLayerDataPointer0',
 'FwpsApplyModifiedLayerData0','FwpsRedirectHandleCreate0','FwpsQueryConnectionRedirectState0'}
class Rejected(ValueError): pass
def need(ok,code):
 if not ok: raise Rejected(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def unique(pairs):
 d={}
 for k,v in pairs:
  need(k not in d,'duplicate_json');d[k]=v
 return d
def decode(raw):return json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique)
def flag(d,k,v):need(d.get(k) is v,'invalid_flag_'+k)
def unpack(raw,expected):
 need(0<len(raw)<4*1024*1024 and sha(raw)==expected,'archive_digest')
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  need(len(z.namelist())==len(set(z.namelist())) and len(z.namelist())<20,'zip_members')
  need(sum(i.file_size for i in z.infolist())<8*1024*1024,'zip_expansion')
  need(all('/' not in n and '\\' not in n and ':' not in n and not n.startswith('.') for n in z.namelist()),'zip_names')
  need(z.testzip() is None,'zip_crc')
  return {n:z.read(n) for n in z.namelist()}
class PE:
 def __init__(self,raw,subsystem):
  self.raw=raw
  need(len(raw)>512 and raw[:2]==b'MZ','dos')
  self.p=self.num(60,'I');need(self.cut(self.p,4)==b'PE\0\0','pe')
  need(self.num(self.p+4,'H')==0x8664,'x64')
  self.o=self.p+24;need(self.num(self.o,'H')==0x20b,'pe32plus')
  need(self.num(self.o+68,'H')==subsystem,'subsystem')
  flags=self.num(self.o+70,'H');need(flags&0x140==0x140,'nx_dynamic_base')
  if subsystem==1:need(flags&0x80,'force_integrity')
  count=self.num(self.p+6,'H');size=self.num(self.p+20,'H')
  need(1<=count<=32 and size>=240,'headers')
  self.sections=[]
  for i in range(count):
   at=self.o+size+i*40
   vs,va,rs,rp=struct.unpack('<IIII',self.cut(at+8,16));f=self.num(at+36,'I')
   need(rp+rs<=len(raw),'section_bounds')
   need(not(f&0x80000000 and f&0x20000000),'writable_executable')
   self.sections.append((va,vs,rp,rs,f))
  entry=self.num(self.o+16,'I')
  need(any(va<=entry<va+vs and f&0x20000000 for va,vs,rp,rs,f in self.sections),'entry')
  self.cert=(self.num(self.o+144,'I'),self.num(self.o+148,'I'))
  need(self.cert==(0,0),'unexpected_certificate')
  va=self.num(self.o+120,'I');size=self.num(self.o+124,'I');need(20<=size<=4096,'imports_size')
  self.imports={}
  for i in range(128):
   oft,stamp,forward,name,ft=struct.unpack('<IIIII',self.cut(self.rva(va)+i*20,20))
   if (oft,stamp,forward,name,ft)==(0,0,0,0,0):break
   dll=self.string(name).lower();need(dll not in self.imports,'duplicate_dll');values=[]
   for j in range(1024):
    value=self.num(self.rva(oft or ft)+8*j,'Q')
    if value==0:break
    if value>>63:
     need(value & 0x7fffffffffff0000 == 0,'invalid_import_ordinal');values.append('ordinal:'+str(value&0xffff))
    else:values.append(self.string(value+2))
   else:raise Rejected('unterminated_thunks')
   self.imports[dll]=values
  else:raise Rejected('unterminated_imports')
 def cut(self,at,n):
  need(0<=at<=len(self.raw) and 0<=n<=len(self.raw)-at,'pe_bounds');return self.raw[at:at+n]
 def num(self,at,fmt):return struct.unpack('<'+fmt,self.cut(at,struct.calcsize('<'+fmt)))[0]
 def rva(self,x):
  if x<self.num(self.o+60,'I'):self.cut(x,1);return x
  m=[s for s in self.sections if s[0]<=x<s[0]+s[3]];need(len(m)==1,'unmapped_rva')
  return m[0][2]+x-m[0][0]
 def string(self,rva):
  i=self.rva(rva);end=self.raw.find(b'\0',i,min(i+256,len(self.raw)));need(end>=i,'import_string')
  return self.raw[i:end].decode('ascii')
def scope(build,negative,transport):
 need(build.get('source_sha')==SOURCE and transport.get('source_sha')==SOURCE,'source_mismatch')
 need(build.get('evidence')=='kernel_redirect_binary_build_and_static_import_audit_only','build_scope')
 for k in ['ok','redirect_calls_linked']:flag(build,k,True)
 for k in ['kernel_driver_loaded','wfp_filters_installed','process_birth_and_ale_native_observed','signature_acceptance','g2_pass','release_accepted']:flag(build,k,False)
 for k,v in [('ok',True),('g2_pass',False),('kernel_load_performed_by_broker',False)]:flag(negative,k,v)
 need(transport.get('transport')=='actual_OpenSSH_dynamic_SOCKS','transport_kind')
 need(type(transport.get('rust_tests_passed')) is int and transport['rust_tests_passed']==13,'test_count')
 for k in ['ok','ipv4_ipv6_exact_response','half_close','private_mount_namespace_verified','fixture_processes_and_keys_removed']:flag(transport,k,True)
 for k in ['host_ssh_service_changed','fixture_context_used','kernel_redirect_executed','g2_pass','release_accepted']:flag(transport,k,False)
def audit(kernel,ssh,socket):
 k=unpack(kernel,PINS['kernel']);t=unpack(ssh,PINS['ssh']);s=unpack(socket,PINS['socket'])
 need(set(k)=={'broker-negative.json','build-result.json','Cargo.lock','generated-wdk.rs','flowbridge_g2_witness.sys','flowbridge-redirect-broker.exe','handoff-tests.exe','ledger-tests.exe'},'kernel_files')
 need(set(t)=={'transport-result.json'} and set(s)=={'ipv4.json','ipv6.json'},'report_files')
 build=decode(k['build-result.json']);transport=decode(t['transport-result.json'])
 scope(build,decode(k['broker-negative.json']),transport)
 driver=k['flowbridge_g2_witness.sys'];broker=k['flowbridge-redirect-broker.exe']
 need(sha(driver)==DRIVER and build.get('driver_sha256')==DRIVER and build.get('size_bytes')==len(driver),'driver_hash')
 need(sha(broker)==BROKER,'broker_hash')
 pe=PE(driver,1);bp=PE(broker,3)
 need(pe.imports==build['imports'],'independent_parser_disagrees')
 need(set(pe.imports)=={'ntoskrnl.exe','hal.dll','fwpkclnt.sys','cng.sys'},'kernel_libraries')
 need(REQUIRED<={n for names in pe.imports.values() for n in names},'redirect_calls_missing')
 bnames={n for names in bp.imports.values() for n in names}
 need({'WSAIoctl','DeviceIoControl','GetFinalPathNameByHandleW','FwpmGetAppIdFromFileName0'}<=bnames,'broker_handoff_calls_missing')
 for family in ['ipv4','ipv6']:
  r=decode(s[family+'.json']);need(r.get('family')==family,'socket_family')
  for n in ['ok','native_windows_called','socket_endpoint_join_native_observed','owned_sockets_and_bfe_session_closed']:flag(r,n,True)
  for n in ['g2_pass','release_accepted','original_unprepared_exe_tested','driver_or_filter_modified']:flag(r,n,False)
  for side in ['client','accepted_local']:
   q=r[side];need(q.get('attribution_scope')=='queried_local_endpoint_only','socket_scope')
   for n in ['g2_pass','creation_epoch_bound','original_process_identity_proved','redirect_admission_allowed']:flag(q,n,False)
   for field in ['records','context']:need(q[field]=={'bytes':0,'state':'query_error','win32_error':10022},'query_error_not_absence')
 return dict(ok=True,source_sha=SOURCE,run_id=RUN,archive_sha256=PINS,
  driver_sha256=DRIVER,broker_sha256=BROKER,driver_bytes=len(driver),broker_bytes=len(broker),
  kernel_redirect_imports_verified=True,broker_wfp_handoff_imports_verified=True,
  independent_pe_parser_used=True,ordinal_imports_preserved_without_name_guessing=True,
  broker_connect_order_proved_by_binary_audit=False,embedded_driver_signature=False,
  windows_broker_rejected_unredirected_sockets=True,real_ssh_transport_ipv4_ipv6_halfclose=True,
  real_transport_test_count=13,compiled_kernel_not_loaded=True,
  full_origin_kernel_redirect_socket_ssh_chain_executed=False,
  independent_human_or_native_reviewer_acceptance=False,g2_pass=False,release_accepted=False)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('kernel',type=Path);p.add_argument('ssh',type=Path);p.add_argument('socket',type=Path);a=p.parse_args()
 try:result=audit(a.kernel.read_bytes(),a.ssh.read_bytes(),a.socket.read_bytes())
 except Rejected as e:result=dict(ok=False,error=str(e),g2_pass=False)
 except Exception:result=dict(ok=False,error='invalid_artifact',g2_pass=False)
 print(json.dumps(result,indent=2,sort_keys=True));return 0 if result['ok'] else 2
if __name__=='__main__':raise SystemExit(main())
