#!/usr/bin/env python3
"""Offline acceptance of a future Windows R136 evidence ZIP; no archive extraction."""
import argparse,hashlib,json,re,zipfile
from pathlib import Path
from r136_oracle import outcome,matrix
SRC_GIT='f45b3ae5274325081d2644f27173b2e667909bd3'
SRC_SHA='165675ec74ba2a70daaa69c014b3473b48a9bf11267014cc1b487978384db6d9'
FLAGS=('kernel_origin_proof','mapped_section_file_id_proof','network_owner_proof','no_direct_proof')
def pairs(kv):
    d={}
    for k,v in kv:
        if k in d:raise ValueError('duplicate JSON key')
        d[k]=v
    return d
def decode(line):return json.loads(line.decode('utf-8-sig'),object_pairs_hook=pairs)
def wide(v):return type(v) is str and 4<=len(v)<=131068 and re.fullmatch('(?:[0-9A-F]{4})+',v) is not None and all(v[i:i+4]!='0000' for i in range(0,len(v),4))
def hexf(v,n):return type(v) is str and len(v)==n and re.fullmatch('[0-9A-F]+',v) is not None
def app(v):return type(v) is str and 2<=len(v)<=131072 and re.fullmatch('(?:[0-9A-F]{2})+',v) is not None

def raw_rows(rows,exit_code):
    if len(rows)!=4 or type(exit_code) is not int or exit_code not in (0,3):raise ValueError('cardinality/exit')
    for r in rows:
        if type(r.get('schema')) is not int or r['schema']!=1 or any(r.get(flag) is not False for flag in FLAGS):raise ValueError('proof boundary')
    p,m,f,s=rows
    if p.get('kind')!='self' or type(p.get('pid')) is not int or not 0<p['pid']<2**32:raise ValueError('process identity shape')
    for k in ('win32_before','win32_after','native_before','native_after','module_name'):
        if not wide(p.get(k)):raise ValueError('process name '+k)
    if m.get('kind')!='mapping' or type(m.get('state')) is not int or type(m.get('type')) is not int:raise ValueError('mapping type')
    for k in ('mapped_native_before','mapped_native_after'):
        if not wide(m.get(k)):raise ValueError('mapped name '+k)
    for k in ('module_base_hex','allocation_base_hex'):
        if not hexf(m.get(k),16):raise ValueError('base address '+k)
    if f.get('kind')!='file':raise ValueError('held file shape')
    for k in ('final_native','final_dos'):
        if not wide(f.get(k)):raise ValueError('file path '+k)
    for k in ('volume_before','volume_after'):
        if not hexf(f.get(k),16):raise ValueError('volume '+k)
    for k in ('id_before','id_after'):
        if not hexf(f.get(k),32):raise ValueError('file id '+k)
    for k in ('app0','app1','app2','app3'):
        if not app(f.get(k)):raise ValueError('opaque WFP AppId '+k)
    bits=(m['state']==0x1000 and m['type']==0x1000000 and m['module_base_hex']==m['allocation_base_hex'],
          m['mapped_native_before']==m['mapped_native_after'],
          m['mapped_native_before']==p['native_before']==p['native_after'],
          m['mapped_native_before']==f['final_native'],
          f['id_before']!='0'*32 and f['volume_before']!='0'*16 and f['id_before']==f['id_after'] and f['volume_before']==f['volume_after'],
          f['app0']==f['app1']==f['app2']==f['app3'],
          p['win32_before']==p['win32_after'],
          p['module_name']==p['win32_before'])
    mask=sum((1<<i) for i,b in enumerate(bits) if b)
    expected_exit=outcome(mask)
    status='MAPPED_IMAGE_NAME_CONCORDANT_NOT_SECTION_FILE_ID_PROOF' if expected_exit==0 else 'MAPPING_OBSERVATION_MISMATCH_NO_PROOF'
    if (s.get('kind')!='summary' or s.get('status')!=status or exit_code!=expected_exit or
        type(s.get('diagnostic_exit')) is not int or s['diagnostic_exit']!=expected_exit or
        type(s.get('observation_mask')) is not int or s['observation_mask']!=mask or
        s.get('atomic_snapshot') is not False or
        type(s.get('mem_image_constant')) is not int or s['mem_image_constant']!=0x1000000 or
        type(s.get('file_id_class')) is not int or s['file_id_class']!=18):raise ValueError('positive summary inconsistent with raw fields')
    return mask

def inspect(path):
    b=Path(path).read_bytes()
    if len(b)>1_000_000:raise ValueError('ZIP over cap')
    with zipfile.ZipFile(path) as z:
        infos=z.infolist();names={i.filename for i in infos}
        if len(infos)!=len(names) or not {'R136_EVIDENCE.json','self-mapped-image.jsonl','self-mapped-image.stdout.txt','contract-matrix.stdout.txt','unit-tests.stdout.txt','test-list.stdout.txt'}<=names:
            raise ValueError('ZIP member set')
        if sum(i.file_size for i in infos)>500_000 or any(i.flag_bits&1 or i.filename !=Path(i.filename).name or '\\' in i.filename for i in infos):raise ValueError('unsafe ZIP members')
        if z.testzip() is not None:raise ValueError('ZIP CRC mismatch')
        if any(z.read(n).strip() for n in names if n.endswith('.stderr.txt')):raise ValueError('nonempty stderr')
        r=decode(z.read('R136_EVIDENCE.json'))
        if (r.get('status') not in ('MAPPED_IMAGE_NAME_CONCORDANT_NOT_SECTION_FILE_ID_PROOF','MAPPING_OBSERVATION_MISMATCH_NO_PROOF') or
            r.get('source_blob_expected')!=SRC_GIT or r.get('source_sha256_expected')!=SRC_SHA or r.get('source_sha256_observed')!=SRC_SHA or
            r.get('target')!='x86_64-pc-windows-msvc' or r.get('native_probe_requested') is not True):raise ValueError('provenance')
        for k in FLAGS+('atomic_snapshot','wfp_policy_modified'):
            if r.get(k) is not False:raise ValueError('false proof')
        for k in ('metadata_exit','tests_exit'):
            if type(r.get(k)) is not int or r[k]!=0:raise ValueError(k)
        if type(r.get('listed_tests')) is not int or r['listed_tests']!=21:raise ValueError('test list count')
        lst=re.findall(r'(?m)^(tests::[^\r\n ]+): test\r?$',z.read('test-list.stdout.txt').decode())
        passed=re.findall(r'(?m)^test (tests::[^\r\n ]+) \.\.\. ok\r?$',z.read('unit-tests.stdout.txt').decode())
        if len(lst)!=21 or len(set(lst))!=21 or sorted(lst)!=sorted(passed):raise ValueError('test listing differs')
        if b'21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' not in z.read('unit-tests.stdout.txt'):raise ValueError('test summary')
        m=z.read('contract-matrix.stdout.txt').replace(b'\r\n',b'\n')
        if m!=matrix() or r.get('matrix_sha256')!=hashlib.sha256(m).hexdigest():raise ValueError('decision matrix')
        raw=z.read('self-mapped-image.jsonl')
        if raw!=z.read('self-mapped-image.stdout.txt'):raise ValueError('raw JSONL differs from stdout')
        if type(r.get('native_probe_exit')) is not int:raise ValueError('native exit not integer')
        mask=raw_rows([decode(line) for line in raw.splitlines()],r['native_probe_exit'])
        if type(r.get('observation_mask')) is not int or r['observation_mask']!=mask:raise ValueError('report mask')
        return {'schema':1,'status':'R136_NATIVE_RECEIPT_ACCEPTED_NOT_ALE_PROOF','archive_sha256':hashlib.sha256(b).hexdigest(),
            'members':len(names),'tests':21,'matrix_states':256,'mask':mask,'diagnostic_exit':r['native_probe_exit'],
            'image_section_file_id_proof':False,'kernel_origin_proof':False,'no_direct_proof':False,
            'raw_appids_published':False,'raw_addresses_published':False}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('archive',type=Path);args=p.parse_args()
    print(json.dumps(inspect(args.archive),indent=2,ensure_ascii=False))
