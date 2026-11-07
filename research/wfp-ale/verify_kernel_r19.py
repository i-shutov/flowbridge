#!/usr/bin/env python3
"""Independent stdlib-only reader of the pinned R19 artifacts. NEVER loads a PE.

Checks structure separately from workflow pefile. A build PASS is not load,
signature, original-process attribution, or a native G2 acceptance.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

SOURCE = 'b8fc020cf5ada3c989ef9a406021bf44012fb78f'
KERNEL_ZIP = '83f214791b55d34c079f3903449a1dae7f5132fd7fcf0e5a9dcaee89ebae3bb6'
SOCKET_ZIP = '58efe756f2642eb82b3a2ca2166713bba1eb87cf050f2feb29c5c9ca1c5cdc72'
DRIVER = 'a48d6122a158de3a2cf912e5f8bc6d6eacf6bee5dde09fada3fbdaaa22ff5acc'
SOCKET_SOURCE = '8289e2f8f48c09c31437d7f0bbc6dc910c315831914bd916a3f195343af5e494'
REQUIRED = {'PsSetCreateProcessNotifyRoutineEx', 'PsGetProcessCreateTimeQuadPart',
            'PsGetProcessStartKey', 'ObfReferenceObject', 'ObfDereferenceObject',
            'FwpsCalloutRegister1', 'FwpsCalloutUnregisterById0'}

class Rejected(ValueError): pass

def demand(ok, code):
    if not ok: raise Rejected(code)

def sha(data): return hashlib.sha256(data).hexdigest()

def unique(pairs):
    out = {}
    for k, v in pairs:
        demand(k not in out, 'duplicate_json_key'); out[k] = v
    return out

def decode(raw): return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique)

def archive(raw, expected, files):
    demand(0 < len(raw) <= 2**20 and sha(raw) == expected, 'archive_digest_or_size')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        demand(len(z.namelist()) == len(files) and set(z.namelist()) == set(files), 'archive_members')
        demand(sum(i.file_size for i in z.infolist()) <= 2**20, 'archive_expansion')
        demand(z.testzip() is None, 'archive_crc')
        return {name: z.read(name) for name in files}

class PE:
    def __init__(self, raw):
        self.raw = raw
        demand(len(raw) >= 512 and raw[:2] == b'MZ', 'pe_dos_header')
        self.pe = self.u32(60)
        demand(self.cut(self.pe, 4) == b'PE\0\0', 'pe_signature')
        demand(self.u16(self.pe + 4) == 0x8664, 'pe_x64')
        count = self.u16(self.pe + 6)
        size = self.u16(self.pe + 20)
        self.opt = self.pe + 24
        demand(self.u16(self.opt) == 0x20b and size >= 240, 'pe_plus_header')
        demand(1 <= count <= 32, 'pe_section_count')
        self.headers = self.u32(self.opt + 60)
        self.entry = self.u32(self.opt + 16)
        demand(self.u16(self.opt + 68) == 1, 'pe_not_native')
        flags = self.u16(self.opt + 70)
        demand(flags & 0x1c0 == 0x1c0, 'pe_security_characteristics')
        self.sections = []
        for i in range(count):
            at = self.opt + size + 40*i
            name = self.cut(at, 8).rstrip(b'\0').decode('ascii')
            vs, va, rs, rp = self.unpack('<IIII', at + 8)
            ch = self.u32(at + 36)
            demand(rp + rs <= len(raw), 'section_outside_file')
            demand(not (ch & 0x20000000 and ch & 0x80000000), 'writable_executable_section')
            self.sections.append((name, vs, va, rs, rp, ch))
        entry_sections = [s for s in self.sections if s[2] <= self.entry < s[2]+s[1]]
        demand(len(entry_sections) == 1 and entry_sections[0][5] & 0x20000000, 'entry_not_executable')
        self.entry_section = entry_sections[0][0]
        demand(self.u32(self.opt+108) >= 16, 'data_directories_missing')
        self.certificate = self.unpack('<II', self.opt + 112 + 4*8)
        demand(self.certificate == (0, 0), 'unexpected_embedded_certificate')
        self.imports = self.read_imports()
    def cut(self, at, size):
        demand(0 <= at <= len(self.raw) and 0 <= size <= len(self.raw)-at, 'pe_bounds')
        return self.raw[at:at+size]
    def unpack(self, fmt, at): return struct.unpack(fmt, self.cut(at, struct.calcsize(fmt)))
    def u16(self, at): return self.unpack('<H', at)[0]
    def u32(self, at): return self.unpack('<I', at)[0]
    def u64(self, at): return self.unpack('<Q', at)[0]
    def rva(self, value):
        if value < self.headers:
            self.cut(value, 1); return value
        matches = [s for s in self.sections if s[2] <= value < s[2]+s[3]]
        demand(len(matches) == 1, 'unmapped_or_ambiguous_rva')
        s = matches[0]; return s[4]+value-s[2]
    def name(self, value):
        start = self.rva(value)
        end = self.raw.find(b'\0', start, min(len(self.raw), start+256))
        demand(end >= start, 'unterminated_import')
        return self.raw[start:end].decode('ascii')
    def read_imports(self):
        va, size = self.unpack('<II', self.opt+112+8)
        demand(va != 0 and 20 <= size <= 4096, 'import_directory_invalid')
        result = {}
        for i in range(min(size//20+1, 128)):
            fields = self.unpack('<IIIII', self.rva(va)+i*20)
            if fields == (0,0,0,0,0): return result
            oft, _, _, name_rva, ft = fields
            name = self.name(name_rva).lower()
            demand(name not in result, 'duplicate_import_dll')
            entries = []
            for j in range(512):
                thunk = self.u64(self.rva(oft or ft)+j*8)
                if thunk == 0: break
                demand(not thunk & (1<<63), 'ordinal_import_not_expected')
                entries.append(self.name(thunk+2))
            else: raise Rejected('import_thunk_limit')
            result[name] = entries
        raise Rejected('unterminated_import_directory')
    def summary(self):
        demand(set(self.imports) == {'ntoskrnl.exe', 'fwpkclnt.sys', 'hal.dll'}, 'unexpected_runtime_library')
        imported = {n for values in self.imports.values() for n in values}
        demand(REQUIRED <= imported, 'missing_witness_api_import')
        demand(not {'FwpmFilterAdd0','FwpsApplyModifiedLayerData0','FwpsRedirectHandleCreate0'} & imported,
               'unexpected_filter_or_redirect_mutation')
        return {'x64_native_pe': True, 'entry_section': self.entry_section,
                'force_integrity_bit': True, 'nx_compatible_bit': True, 'dynamic_base_bit': True,
                'embedded_certificate_present': False, 'writable_executable_sections': False,
                'runtime_import_libraries': sorted(self.imports),
                'required_process_and_ale_api_imports': sorted(REQUIRED)}

def audit(kernel_raw, socket_raw):
    k = archive(kernel_raw, KERNEL_ZIP, ['build-result.json','Cargo.lock','flowbridge_g2_witness.sys','generated-wdk.rs'])
    d = k['flowbridge_g2_witness.sys']; demand(sha(d) == DRIVER, 'driver_digest')
    r = decode(k['build-result.json'])
    demand(r.get('ok') is True and r.get('source_sha') == SOURCE and r.get('driver_sha256') == DRIVER, 'build_provenance')
    demand(type(r.get('size_bytes')) is int and r['size_bytes'] == len(d), 'binary_size')
    demand(r.get('evidence') == 'kernel_binary_build_and_static_import_audit_only', 'build_scope')
    for flag in ['kernel_driver_loaded','wfp_filters_installed','process_birth_and_ale_native_observed','signature_acceptance','g2_pass','release_accepted']:
        demand(r.get(flag) is False, 'promoted_build_'+flag)
    pe = PE(d); summary = pe.summary()
    demand(pe.imports == r['imports'], 'independent_import_parser_disagrees')
    sockets = archive(socket_raw, SOCKET_ZIP, ['ipv4.json','ipv6.json'])
    for f in ['ipv4','ipv6']:
        o = decode(sockets[f+'.json'])
        demand(o.get('source_sha256') == SOCKET_SOURCE and o.get('family') == f, 'socket_source_or_family')
        for flag in ['ok','native_windows_called','socket_endpoint_join_native_observed','owned_sockets_and_bfe_session_closed','endpoint_appids_equal_observation']:
            demand(o.get(flag) is True, 'socket_observation_missing')
        for flag in ['g2_pass','release_accepted','original_unprepared_exe_tested','driver_or_filter_modified','endpoint_ids_equal_observation']:
            demand(o.get(flag) is False, 'socket_scope_promoted')
        demand(o.get('scope') == 'owned_loopback_sockets_no_payload', 'socket_scope')
        for side in ['client','accepted_local']:
            q = o[side]
            demand(q.get('attribution_scope') == 'queried_local_endpoint_only', 'socket_owner_promoted')
            for flag in ['creation_epoch_bound','g2_pass','ndisrd_frame_bound','original_process_identity_proved','process_start_key_bound','redirect_admission_allowed','release_accepted','system_no_direct_proved']:
                demand(q.get(flag) is False, 'socket_owner_promoted')
            for what in ['records','context']:
                demand(q[what] == {'bytes':0, 'state':'query_error', 'win32_error':10022}, 'redirect_error_promoted_to_absence')
    return {'ok':True,'scope':'unsigned_kernel_build_plus_local_socket_native_observations',
            'source_sha':SOURCE,'run_id':42381023741,
            'kernel_artifact_id':13577538218,'socket_artifact_id':13576609950,
            'kernel_zip_sha256':KERNEL_ZIP,'socket_zip_sha256':SOCKET_ZIP,
            'driver_sha256':DRIVER,'driver_bytes':len(d),'pe':summary,
            'retained_cargo_lock_sha256':sha(k['Cargo.lock']),
            'retained_wdk_bindings_sha256':sha(k['generated-wdk.rs']),
            'local_socket_ipv4_ipv6_observed':True,'kernel_driver_loaded':False,
            'redirect_implemented_in_kernel_candidate':False,
            'signature_accepted':False,'independent_human_review':False,
            'g2_pass':False,'release_accepted':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('kernel_zip',type=Path);p.add_argument('socket_zip',type=Path)
    args=p.parse_args()
    try:
        with args.kernel_zip.open('rb') as f: k=f.read(2**20+1)
        with args.socket_zip.open('rb') as f: s=f.read(2**20+1)
        result=audit(k,s)
    except Rejected as err: result={'ok':False,'error':str(err),'g2_pass':False}
    except Exception: result={'ok':False,'error':'invalid_artifact','g2_pass':False}
    print(json.dumps(result,indent=2,sort_keys=True));return 0 if result['ok'] else 2
if __name__=='__main__': raise SystemExit(main())
