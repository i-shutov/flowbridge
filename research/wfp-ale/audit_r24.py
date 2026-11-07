"""Offline verification of pinned build/native-negative/transport-only evidence.
Never executes a Windows binary, installs a driver, or treats sublink PASS as G2.
"""
from pathlib import Path, PurePosixPath
import argparse, hashlib, io, json, struct, zipfile

PINS = json.loads('{\n  "source_sha": "cf80986e85bb93a50d2a780f05123216a4e271af",\n  "run_id": 42403336045,\n  "kernel_artifact_id": 13586198402,\n  "ssh_artifact_id": 13585934026,\n  "socket_artifact_id": 13586477437,\n  "kernel_zip_sha256": "8315885a043dc5d9e4c7f8e33a93050903293189099184e7e950678b313f1c16",\n  "ssh_zip_sha256": "232a46928cd1e1219ef0f10c862afc4840002c0ecbd3f76eab2b5466b9c680ff",\n  "socket_zip_sha256": "db1f8eb06628aa02e4e7246627b9b2966fe466392a8321b3c825fe98df8d30c9",\n  "source_git_blobs": {\n    "policy_plan.rs": "2aa7468f8d63b8a74f8837d0de98becd8e4f22b6",\n    "policy_windows.rs": "b487ce24840e2295a8d12cc380fcfae946b0b4e5",\n    "broker_windows.rs": "f315d2cfab16ed7474446a9bb819980c8c737163",\n    "broker.rs": "825cb0a053dca0259a81fe77cdad9227c71883ae",\n    "kernel/src/redirect.rs": "5b09b668bb331e64c11a1094e52d2714562c25e0",\n    "ownership_check_r24.py": "c122f1fc0d5d98179c97716c8a9581a5e4fa2e2a"\n  }\n}\n')

class Rejected(ValueError): pass

def require(value, why):
    if not value: raise Rejected(why)

def sha(data): return hashlib.sha256(data).hexdigest()

def obj(pairs):
    result={}
    for k,v in pairs:
        require(k not in result,'duplicate_json_key');result[k]=v
    return result

def decode(raw): return json.loads(raw.decode('utf-8-sig'),object_pairs_hook=obj)

def readzip(raw, digest=None):
    require(0 < len(raw) <= 16*1024*1024,'zip_size')
    if digest: require(sha(raw)==digest,'artifact_sha')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        names=z.namelist()
        require(len(names)==len(set(names)) and len(names)<=128,'zip_members')
        require(sum(v.file_size for v in z.infolist())<=32*1024*1024,'expanded_size')
        for name in names:
            require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts and '\\' not in name and ':' not in name,'zip_path')
        require(z.testzip() is None,'zip_crc')
        return {n:z.read(n) for n in names}

class Image:
    def __init__(self,data,subsystem):
        self.data=data
        require(len(data)>512 and data[:2]==b'MZ','dos_header')
        pe=self.number(60,4)
        require(self.take(pe,4)==b'PE\0\0','pe_header')
        require(self.number(pe+4,2)==0x8664,'not_x64')
        self.opt=pe+24
        require(self.number(self.opt,2)==0x20b,'not_pe32plus')
        require(self.number(self.opt+68,2)==subsystem,'subsystem')
        self.flags=self.number(self.opt+70,2)
        require(self.flags & 0x140 == 0x140,'nx_aslr')
        self.header_size=self.number(self.opt+60,4)
        self.entry=self.number(self.opt+16,4)
        sections=self.number(pe+6,2);size=self.number(pe+20,2)
        require(0<sections<=32 and size>=240,'section_header')
        self.sections=[]
        for i in range(sections):
            p=self.opt+size+i*40
            vs,va,rs,rp=struct.unpack('<IIII',self.take(p+8,16));flags=self.number(p+36,4)
            require(rp+rs<=len(data),'section_range')
            require(not(flags & 0x80000000 and flags & 0x20000000),'writable_executable')
            self.sections.append((vs,va,rs,rp,flags))
        entry=[s for s in self.sections if s[1]<=self.entry<s[1]+s[0]]
        require(len(entry)==1 and entry[0][4]&0x20000000,'entry_not_code')
        self.certificate=(self.number(self.opt+144,4),self.number(self.opt+148,4))
        self.imports=self.parse_imports()
    def take(self,p,n):
        require(0<=p<=len(self.data) and 0<=n<=len(self.data)-p,'pe_bounds')
        return self.data[p:p+n]
    def number(self,p,n):return int.from_bytes(self.take(p,n),'little')
    def rva(self,r):
        if r<self.header_size:self.take(r,1);return r
        s=[s for s in self.sections if s[1]<=r<s[1]+s[2]]
        require(len(s)==1,'rva_range');return s[0][3]+r-s[0][1]
    def name(self,r):
        p=self.rva(r);e=self.data.find(b'\0',p,min(p+256,len(self.data)))
        require(e>=p,'unterminated_name');return self.data[p:e].decode('ascii')
    def parse_imports(self):
        r=self.number(self.opt+120,4);size=self.number(self.opt+124,4)
        require(r and 20<=size<=4096,'import_directory');table=self.rva(r);out={}
        for i in range(128):
            oft,_,_,name,ft=struct.unpack('<IIIII',self.take(table+i*20,20))
            if not any((oft,name,ft)):return out
            dll=self.name(name).lower();require(dll not in out,'duplicate_import_library');items=[]
            for j in range(1024):
                t=self.number(self.rva(oft or ft)+j*8,8)
                if not t:break
                if t&(1<<63):items.append('ordinal:'+str(t&0xffff))
                else:items.append(self.name(t+2))
            else:raise Rejected('unterminated_thunks')
            out[dll]=items
        raise Rejected('unterminated_imports')

def verify_report(scope,ownership,transport,source):
    require(scope.get('ok') is True and scope.get('source_sha')==source,'build_scope_source')
    require(type(scope.get('actual_broker_tests_passed')) is int and scope['actual_broker_tests_passed']==27,'broker_test_count')
    for k in ['scoped_policy_code_compiled','accepted_socket_ownership_compile_tests']:
        require(scope.get(k) is True,'build_scope_missing')
    for k in ['actual_policy_installed','kernel_driver_loaded','full_redirect_chain_executed','g2_pass','release_accepted']:
        require(scope.get(k) is False,'unsafe_scope_promotion')
    require(ownership.get('ok') is True,'ownership_harness_failed')
    expected={'control','context_not_public','receipt_not_cloneable','accepted_socket_moved','borrowed_socket_cannot_detach_receipt','admitted_upstream_not_public'}
    checks=ownership.get('actual_source_compile_checks')
    require(type(checks) is dict and set(checks)==expected and all(v is True for v in checks.values()),'ownership_cases_missing')
    for k in ['compiled_programs_executed','kernel_redirect_executed','g2_pass']:
        require(ownership.get(k) is False,'ownership_scope_promoted')
    require(transport.get('ok') is True and transport.get('source_sha')==source,'transport_source')
    require(transport.get('transport')=='actual_OpenSSH_dynamic_SOCKS','wrong_transport')
    require(type(transport.get('rust_tests_passed')) is int and transport['rust_tests_passed']==21,'transport_test_count')
    for k in ['ipv4_ipv6_exact_response','half_close','private_mount_namespace_verified','fixture_processes_and_keys_removed']:
        require(transport.get(k) is True,'transport_positive_missing')
    for k in ['kernel_redirect_executed','host_ssh_service_changed','fixture_context_used','g2_pass','release_accepted']:
        require(transport.get(k) is False,'transport_scope_promoted')
    return True

def verify_socket_archive(files):
    require(set(files)=={'ipv4.json','ipv6.json'},'socket_members')
    for family in ['ipv4','ipv6']:
        d=decode(files[family+'.json'])
        require(d.get('family')==family and d.get('scope')=='owned_loopback_sockets_no_payload','socket_scope')
        require(d.get('source_sha256')=='8289e2f8f48c09c31437d7f0bbc6dc910c315831914bd916a3f195343af5e494','socket_source')
        for key in ['ok','native_windows_called','socket_endpoint_join_native_observed','owned_sockets_and_bfe_session_closed']:
            require(d.get(key) is True,'socket_observation_missing')
        for key in ['driver_or_filter_modified','original_unprepared_exe_tested','g2_pass','release_accepted']:
            require(d.get(key) is False,'socket_scope_promoted')
        for side in ['client','accepted_local']:
            q=d.get(side,{})
            require(q.get('attribution_scope')=='queried_local_endpoint_only','remote_owner_inferred')
            require(q.get('local_socket_endpoint_appid_observed') is True,'endpoint_not_observed')
            for key in ['creation_epoch_bound','ndisrd_frame_bound','original_process_identity_proved','process_start_key_bound','redirect_admission_allowed','system_no_direct_proved','g2_pass','release_accepted']:
                require(q.get(key) is False,'socket_origin_promoted')
            for key in ['records','context']:
                value=q.get(key,{})
                require(value.get('state')=='query_error' and type(value.get('win32_error')) is int and value['win32_error']==10022 and type(value.get('bytes')) is int and value['bytes']==0,'query_error_not_preserved')

def audit(kernel,ssh,socket_zip):
    pins=PINS
    k=readzip(kernel,pins['kernel_zip_sha256']);t=readzip(ssh,pins['ssh_zip_sha256']);so=readzip(socket_zip,pins['socket_zip_sha256'])
    verify_socket_archive(so)
    required={'flowbridge_g2_witness.sys','flowbridge-redirect-broker.exe','build-result.json','r24-build-scope.json','ownership-contract.json','broker-negative.json','policy-plan-native.json','sources-r24.zip','source-manifest-r24.json','broker.Cargo.lock','Cargo.lock'}
    require(required<=set(k),'missing_artifacts')
    require(set(t)=={'transport-result.json'},'ssh_artifact_members')
    scope=decode(k['r24-build-scope.json']);own=decode(k['ownership-contract.json']);transport=decode(t['transport-result.json'])
    verify_report(scope,own,transport,pins['source_sha'])
    for n in ['broker-negative.json','policy-plan-native.json']:
        d=decode(k[n]);require(d.get('ok') is True and d.get('g2_pass') is False and d.get('kernel_load_performed_by_broker') is False,'native_negative_scope')
    manifest=decode(k['source-manifest-r24.json']);require(manifest['source_sha']==pins['source_sha'],'source_manifest')
    src=readzip(k['sources-r24.zip']);require(set(src)==set(manifest['files']),'source_members')
    for name,raw in src.items():
        m=manifest['files'][name];lf=raw.replace(b'\r\n',b'\n')
        require(sha(raw)==m['sha256'] and len(raw)==m['bytes'],'source_sha_mismatch')
        require(hashlib.sha1(f'blob {len(lf)}\0'.encode()+lf).hexdigest()==m['normalized_lf_git_blob_sha1'],'source_blob_mismatch')
    for name,expected_blob in pins['source_git_blobs'].items():
        require(name in src,'pinned_source_missing')
        raw=src[name].replace(b'\r\n',b'\n')
        require(hashlib.sha1(f'blob {len(raw)}\0'.encode()+raw).hexdigest()==expected_blob,'source_not_pinned_git_blob')
    require(own['windows_adapter_sha256']==sha(src['broker_windows.rs']),'adapter_not_tested_source')
    driver=Image(k['flowbridge_g2_witness.sys'],1);broker=Image(k['flowbridge-redirect-broker.exe'],3)
    require(driver.flags&0x80 and driver.certificate==(0,0),'driver_unsigned_scope')
    dimports={n for a in driver.imports.values() for n in a}
    for n in ['PsSetCreateProcessNotifyRoutineEx','PsGetProcessStartKey','FwpsRedirectHandleCreate0','FwpsQueryConnectionRedirectState0','FwpsAcquireWritableLayerDataPointer0','FwpsApplyModifiedLayerData0']:
        require(n in dimports,'kernel_redirect_import_missing')
    bimports={n for a in broker.imports.values() for n in a}
    for n in ['WSAIoctl','DeviceIoControl','FwpmTransactionBegin0','FwpmTransactionCommit0','FwpmFilterAdd0','FwpmCalloutAdd0','FwpmCalloutGetByKey0','FwpmFilterGetByKey0']:
        require(n in bimports,'native_activation_import_missing')
    b=decode(k['build-result.json']);require(b.get('source_sha')==pins['source_sha'] and b.get('driver_sha256')==sha(k['flowbridge_g2_witness.sys']),'binary_manifest')
    require(b.get('ok') is True and b.get('evidence')=='kernel_redirect_binary_build_and_static_import_audit_only','kernel_build_scope')
    require(b.get('imports')==driver.imports,'independent_pe_imports_disagree')
    require(set(driver.imports)=={'ntoskrnl.exe','fwpkclnt.sys','hal.dll','cng.sys'},'kernel_runtime_dependency')
    for key in ['kernel_driver_loaded','wfp_filters_installed','process_birth_and_ale_native_observed','signature_acceptance','g2_pass','release_accepted']:
        require(b.get(key) is False,'kernel_manifest_scope')
    return {'ok':True,'source_sha':pins['source_sha'],'run_id':pins['run_id'],
      'kernel_zip_sha256':pins['kernel_zip_sha256'],'ssh_zip_sha256':pins['ssh_zip_sha256'],
      'driver_sha256':sha(k['flowbridge_g2_witness.sys']),'broker_sha256':sha(k['flowbridge-redirect-broker.exe']),
      'driver_bytes':len(k['flowbridge_g2_witness.sys']),'broker_bytes':len(k['flowbridge-redirect-broker.exe']),
      'socket_zip_sha256':pins['socket_zip_sha256'],'native_readonly_socket_ipv4_ipv6':True,
      'actual_ssh_rust_tests_passed':transport['rust_tests_passed'],
      'verifier_executed_binaries':False,'verified_source_files':len(src),'actual_broker_tests_passed':scope['actual_broker_tests_passed'],
      'compiler_enforced_socket_ownership':True,'actual_ssh_transport_ipv4_ipv6_halfclose':True,
      'kernel_redirect_and_bfe_controller_built':True,'driver_embedded_signature_present':False,
      'actual_policy_installed':False,'kernel_driver_loaded':False,'full_native_chain_accepted':False,
      'independent_human_review':False,'g2_pass':False,'release_accepted':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('kernel_zip',type=Path);p.add_argument('ssh_zip',type=Path);p.add_argument('socket_zip',type=Path);a=p.parse_args()
    try:r=audit(a.kernel_zip.read_bytes(),a.ssh_zip.read_bytes(),a.socket_zip.read_bytes())
    except Rejected as e:r={'ok':False,'error':str(e),'g2_pass':False}
    except Exception:r={'ok':False,'error':'invalid_artifact','g2_pass':False}
    print(json.dumps(r,indent=2,sort_keys=True));return 0 if r['ok'] else 2
if __name__=='__main__':raise SystemExit(main())
