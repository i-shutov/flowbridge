#!/usr/bin/env python3
"""Independent, bounded receipt verification. Read ZIP in-memory; never extract/execute."""
import argparse,hashlib,json,re,zipfile
from pathlib import Path

EXPECTED_SRC_GIT='06825134c15d609abbf9f2b2f72248fdffe85f60'
EXPECTED_SRC_SHA='863da6390116e4806dea135311120c121e0760eeed29891c0548828ba1ce8f25'
EXPECTED_MATRIX='bae850d1de8c78c1acbf4aee36fb1a1a67a54c6b72c7c6e09677c774442385ec'
PROOFS=('kernel_origin_proof','image_section_identity_proof','no_direct_proof')
NAMES={"contract-matrix.stderr.txt","contract-matrix.stdout.txt","metadata.stderr.txt","metadata.stdout.txt","probe-build.stderr.txt","probe-build.stdout.txt","R134_EVIDENCE.json","rustc-version.stderr.txt","rustc-version.stdout.txt","self-image.jsonl","self-image.stderr.txt","self-image.stdout.txt","test-build.stderr.txt","test-build.stdout.txt","test-list.stderr.txt","test-list.stdout.txt","unit-tests.stderr.txt","unit-tests.stdout.txt"}

def unique_pairs(items):
    out={}
    for k,v in items:
        if k in out:raise ValueError('duplicate JSON key '+k)
        out[k]=v
    return out

def parse_json(x):return json.loads(x.decode('utf-8-sig'),object_pairs_hook=unique_pairs)
def hex_upper(s,n):return type(s) is str and len(s)==n and re.fullmatch('[0-9A-F]+',s) is not None
def wide(s):return type(s) is str and 4<=len(s)<=131068 and re.fullmatch('(?:[0-9A-F]{4})+',s) and all(s[i:i+4]!='0000' for i in range(0,len(s),4))
def opaque(s):return type(s) is str and 2<=len(s)<=131072 and re.fullmatch('(?:[0-9A-F]{2})+',s) is not None
def same_id(a,b):return a['id_before']!='0'*32 and b['id_before']!='0'*32 and a['volume_before']==b['volume_before'] and a['id_before']==b['id_before']

def validate_rows(rows,exit_code):
    if len(rows)!=5 or type(exit_code) is not int or exit_code not in (0,3):raise ValueError('bad record count/exit')
    for r in rows:
        if type(r.get('schema')) is not int or r['schema']!=1 or any(r.get(k) is not False for k in PROOFS):raise ValueError('proof boundary')
    proc,a,b,apps,summary=rows
    if proc.get('kind')!='self_process' or type(proc.get('pid')) is not int or not (0<proc['pid']<2**32) or not wide(proc.get('dos_name_hex')) or not wide(proc.get('native_name_hex')) or type(proc.get('names_stable')) is not bool:raise ValueError('self process shape')
    for i,f in enumerate((a,b)):
        if f.get('kind')!='file' or type(f.get('index')) is not int or f['index']!=i:raise ValueError('file index')
        for k,n in [('volume_before',16),('volume_after',16),('id_before',32),('id_after',32)]:
            if not hex_upper(f.get(k),n):raise ValueError('file id shape '+k)
        if not wide(f.get('final_dos_hex')) or not wide(f.get('final_native_hex')):raise ValueError('file name shape')
    if apps.get('kind')!='appid' or type(apps.get('queries')) is not int or apps['queries']!=4 or apps.get('opaque_bytes') is not True:raise ValueError('appid shape')
    for k in ('process_path_before','final_path_before','process_path_after','final_path_after'):
        if not opaque(apps.get(k)):raise ValueError('appid opaque '+k)
    flags=[a['id_before']!='0'*32 and b['id_before']!='0'*32,
           same_id(a,b),
           all(f['volume_before']==f['volume_after'] and f['id_before']==f['id_after'] for f in (a,b)),
           True,
           apps['process_path_before']==apps['process_path_after'] and apps['final_path_before']==apps['final_path_after'],
           apps['process_path_before']==apps['final_path_before'],
           proc['names_stable'],
           proc['native_name_hex']==a['final_native_hex']==b['final_native_hex']]
    mask=sum(1<<i for i,x in enumerate(flags) if x)
    code=0 if mask&127==127 else 3
    status='SELF_IMAGE_FILE_APPID_OBSERVED_NOT_ALE_PROOF' if code==0 else 'OBSERVATION_MISMATCH_NO_PROOF'
    if (summary.get('kind')!='summary' or summary.get('status')!=status or exit_code!=code or
        summary.get('atomic_snapshot') is not False or
        any(type(summary.get(k)) is not int or summary[k]!=v for k,v in [('observations_mask',mask),('diagnostic_exit',code),('share_mode',1),('file_id_class',18),('read_only_file_handles',2)])):
        raise ValueError('summary inconsistent with raw observations')
    return mask

def inspect_zip(path):
    b=path.read_bytes()
    if len(b)>1_000_000:raise ValueError('archive over cap')
    with zipfile.ZipFile(path) as z:
        infos=z.infolist();names={i.filename for i in infos}
        if len(infos)!=18 or names!=NAMES or sum(i.file_size for i in infos)>500_000:raise ValueError('archive name/size mismatch')
        if any(i.flag_bits&1 or '/' in i.filename or '\\' in i.filename for i in infos):raise ValueError('unsafe zip member')
        if z.testzip() is not None:raise ValueError('CRC mismatch')
        if any(z.read(n).strip() for n in NAMES if n.endswith('.stderr.txt')):raise ValueError('nonempty stderr')
        r=parse_json(z.read('R134_EVIDENCE.json'))
        if (r.get('status')!='SELF_IMAGE_FILE_APPID_OBSERVED_NOT_ALE_PROOF' or r.get('reason') is not None or
            r.get('source_blob_expected')!=EXPECTED_SRC_GIT or r.get('source_sha256_observed')!=EXPECTED_SRC_SHA or r.get('source_sha256_expected')!=EXPECTED_SRC_SHA or
            r.get('target')!='x86_64-pc-windows-msvc' or r.get('native_probe_requested') is not True):raise ValueError('source/status provenance')
        for k in ('metadata_exit','unit_tests_exit','native_probe_exit'):
            if type(r.get(k)) is not int or r[k]!=0:raise ValueError(k+' not PASS')
        if type(r.get('listed_tests')) is not int or r['listed_tests']!=18:raise ValueError('listed test count')
        for k in PROOFS+('policy_enumeration_performed','wfp_policy_modified','atomic_snapshot'):
            if r.get(k) is not False:raise ValueError('false proof boundary promoted '+k)
        m=z.read('contract-matrix.stdout.txt').replace(b'\r\n',b'\n')
        expected=b''.join(f'{i:03d}:{0 if (i&127)==127 else 3}\n'.encode('ascii') for i in range(256))
        if m!=expected or hashlib.sha256(m).hexdigest()!=EXPECTED_MATRIX or r.get('contract_matrix_sha256')!=EXPECTED_MATRIX:raise ValueError('matrix mismatch')
        listed=re.findall(r'(?m)^(tests::[^\r\n ]+): test\r?$',z.read('test-list.stdout.txt').decode('utf-8'))
        passed=re.findall(r'(?m)^test (tests::[^\r\n ]+) \.\.\. ok\r?$',z.read('unit-tests.stdout.txt').decode('utf-8'))
        if len(listed)!=18 or len(set(listed))!=18 or sorted(listed)!=sorted(passed):raise ValueError('listed/passed mismatch')
        if b'18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' not in z.read('unit-tests.stdout.txt'):raise ValueError('test summary')
        raw=z.read('self-image.jsonl')
        if raw!=z.read('self-image.stdout.txt'):raise ValueError('raw stdout differs from jsonl')
        rows=[parse_json(x) for x in raw.splitlines()]
        mask=validate_rows(rows,0)
        if type(r.get('observations_mask')) is not int or r['observations_mask']!=mask:raise ValueError('report mask')
        binaries={}
        for k in ('test_exe_sha256','inspector_sha256'):
            if not isinstance(r.get(k),str) or re.fullmatch('[0-9a-f]{64}',r[k]) is None:raise ValueError('reported binary hash format')
            binaries[k]=r[k]
        return {'schema':1,'status':'R134_NATIVE_LOGS_ACCEPTED_NOT_ORIGIN_PROOF',
            'archive_sha256':hashlib.sha256(b).hexdigest(),'members':18,'crc':'OK',
            'source_git_blob_reported':EXPECTED_SRC_GIT,'source_sha256_reported':EXPECTED_SRC_SHA,
            'rustc_host_reported':'x86_64-pc-windows-msvc',
            'native_os_reported':r.get('windows_build'),'native_rustc_reported':r.get('rustc_version'),
            'tests_listed_and_passed':18,'matrix_states':256,'matrix_sha256':EXPECTED_MATRIX,
            'two_file_handles':2,'file_ids_stable_and_equal':bool(mask & 7==7),
            'appid_four_equal':bool(mask & 0x38==0x38),'names_stable':bool(mask&64),
            'native_names_equal':bool(mask&128),'observations_mask':mask,
            'binary_sha256_reported':binaries,'binary_files_received':False,
            'raw_sensitive_paths_published':False,'appids_published':False,
            'image_section_identity_proof':False,'kernel_origin_proof':False,'no_direct_proof':False,
            'native_replay_performed_by_this_auditor':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('--output',type=Path);args=p.parse_args()
    report=inspect_zip(args.archive)
    txt=json.dumps(report,indent=2,ensure_ascii=False)+'\n'
    if args.output:args.output.write_text(txt,encoding='utf-8')
    print(txt)
