#!/usr/bin/env python3
"""Bounded read-only R137 evidence validator; never extract or execute ZIP members."""
import argparse, hashlib, importlib.util, json, re
from pathlib import Path
from zipfile import ZipFile
ROOT=Path(__file__).resolve().parent

def pairs(items):
    d={}
    for k,v in items:
        if k in d: raise ValueError('duplicate JSON key')
        d[k]=v
    return d

def dependencies():
    p=ROOT.parent/'r137'
    pins=json.loads((ROOT/'r137_validator_pins.json').read_text())
    for name,expected in pins.items():
        b=(p/name).read_bytes()
        if hashlib.sha1(f'blob {len(b)}\0'.encode()+b).hexdigest()!=expected:
            raise ValueError('changed validator dependency '+name)
    spec=importlib.util.spec_from_file_location('prior',p/'r137_acceptance.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m

def validate(path):
    m=dependencies(); raw=path.read_bytes()
    if len(raw)>2_000_000: raise ValueError('archive size')
    with ZipFile(path) as z:
        infos=z.infolist();names=[i.filename for i in infos]
        expected={'R137_EVIDENCE.json','missing-name.jsonl'}
        for group in ('contract-matrix','metadata','missing-name','probe-build','rustc-version','test-build','test-list','unit-tests'):
            expected.update((group+'.stdout.txt',group+'.stderr.txt'))
        if set(names)!=expected or len(names)!=len(expected): raise ValueError('archive names/cardinality')
        if sum(i.file_size for i in infos)>2_000_000 or any(i.flag_bits&1 for i in infos): raise ValueError('expanded size/encryption')
        if z.testzip() is not None: raise ValueError('CRC error')
        load=lambda b:json.loads(b.decode('utf-8-sig'),object_pairs_hook=pairs)
        r=load(z.read('R137_EVIDENCE.json'))
        for k in ('metadata_exit','unit_tests_exit'):
            if type(r.get(k)) is not int or r[k]!=0: raise ValueError('failed compiler/tests '+k)
        if r.get('listed_tests')!=18 or type(r['listed_tests']) is not int: raise ValueError('test count')
        source_blob='1b7ba8f0097811a3f636100cd843a26764b4238a'
        source_sha='766f0495b4489958cdde0fbdfc3d9085fc55c780eaf58c91de524f10376be77d'
        if r.get('source_blob_expected')!=source_blob or r.get('source_sha256_expected')!=source_sha or r.get('source_sha256_observed')!=source_sha:
            raise ValueError('source pins')
        if r.get('native_probe_requested') is not True: raise ValueError('native probe not requested')
        for k in ('kernel_origin_proof','image_section_identity_proof','no_direct_proof','policy_enumeration_performed','wfp_policy_modified','atomic_snapshot','test_creates_file'):
            if r.get(k) is not False: raise ValueError('unsupported proof or action '+k)
        listed=re.findall(r'(?m)^([^\r\n]+): test\r?$',z.read('test-list.stdout.txt').decode())
        passed=re.findall(r'(?m)^test ([^\r\n ]+) \.\.\. ok\r?$',z.read('unit-tests.stdout.txt').decode())
        if len(listed)!=18 or len(set(listed))!=18 or sorted(listed)!=sorted(passed): raise ValueError('listed/executed test mismatch')
        if b'18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' not in z.read('unit-tests.stdout.txt'): raise ValueError('test summary')
        # A successful compiler may emit warnings. Keep them visible, not pretend stderr was empty.
        warnings={}
        for n in names:
            if n.endswith('.stderr.txt') and z.read(n).strip():
                if n not in ('metadata.stderr.txt','test-build.stderr.txt','probe-build.stderr.txt'): raise ValueError('runtime stderr '+n)
                text=z.read(n).decode('utf-8-sig')
                if re.search(r'(?m)^error(?:\[|:)',text) or not re.search(r'(?m)^warning:',text): raise ValueError('unrecognized compiler diagnostics')
                warnings[n]={'sha256':hashlib.sha256(z.read(n)).hexdigest(),'warning_headers':re.findall(r'(?m)^warning:.*$',text)}
        matrix=z.read('contract-matrix.stdout.txt').replace(b'\r\n',b'\n')
        if matrix!=m.o.matrix().encode('ascii') or hashlib.sha256(matrix).hexdigest()!=r.get('contract_matrix_sha256'): raise ValueError('oracle mismatch')
        if z.read('missing-name.jsonl')!=z.read('missing-name.stdout.txt'): raise ValueError('raw log copies differ')
        rows=[load(x) for x in z.read('missing-name.jsonl').splitlines()]
        mask=m.validate(rows,r['native_probe_exit'])
        if mask!=r.get('observations_mask') or rows[-1]['status']!=r.get('status'): raise ValueError('report/result mismatch')
        codes=[rows[0]['lookup_code_first'],rows[0]['lookup_code_second']]
        rejected=(codes==[2,2] and mask==15 and r['native_probe_exit']==4)
        for k in ('test_exe_sha256','inspector_sha256'):
            if not re.fullmatch('[0-9a-f]{64}',r.get(k,'')): raise ValueError('binary hash format')
        return dict(schema=1,result='R137_RECEIVED_LOGS_VALIDATED_NOT_KERNEL_PROOF',
            archive_sha256=hashlib.sha256(raw).hexdigest(),source='owner-uploaded evidence-only(3).zip',
            members={n:dict(bytes=len(z.read(n)),sha256=hashlib.sha256(z.read(n)).hexdigest()) for n in sorted(names)},
            native_tests=18,matrix_states=256,matrix_sha256=hashlib.sha256(matrix).hexdigest(),
            diagnostic_exit=r['native_probe_exit'],observation_status=r['status'],observations_mask=mask,
            raw_api_codes=codes,absence_before_after=rows[0]['missing_before'] and rows[0]['missing_after'],
            own_appid_bytes=rows[0]['own_appid_bytes'],missing_name_appid_bytes=rows[0]['missing_name_appid_bytes'],
            absent_path_hypothesis='NOT_CONFIRMED_ON_THIS_HOST' if rejected else 'SEE_RAW_OBSERVATION',
            compiler_warnings=warnings,windows_build_reported=r['windows_build'],rustc_version_reported=r['rustc_version'],
            source_blob_reported=source_blob,source_sha256_reported=source_sha,
            binary_sha256_reported={k:r[k] for k in ('test_exe_sha256','inspector_sha256')},
            binaries_received=False,binaries_independently_rehashed=False,host_clock_attested=False,
            universal_absent_path_rejection_proved=False,kernel_origin_proof=False,no_direct_proof=False)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    text=json.dumps(validate(a.archive),ensure_ascii=False,indent=2)+'\n'
    if a.output:a.output.write_text(text,encoding='utf-8')
    print(text)
