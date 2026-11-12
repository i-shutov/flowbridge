#!/usr/bin/env python3
"""Read-only bounded validation of received R133 logs; never extract/execute ZIP."""
import argparse,hashlib,importlib.util,json,re,sys
from pathlib import Path
from zipfile import ZipFile
ROOT=Path(__file__).resolve().parent

def strict_pairs(items):
    out={}
    for k,v in items:
        if k in out:raise ValueError('duplicate JSON key')
        out[k]=v
    return out

def load_prior():
    prior=ROOT.parent/'r133'
    pins={'r133_acceptance.py':'b185396913b1674e98869eb296c6d06f42450323',
          'r133_oracle.py':'9836ad64a41a2c6bd87017a1bf825ee6e80485fa'}
    for name,pin in pins.items():
        b=(prior/name).read_bytes()
        if hashlib.sha1(f'blob {len(b)}\0'.encode()+b).hexdigest()!=pin:raise ValueError('validator dependency changed')
    spec=importlib.util.spec_from_file_location('r133_accepted_validator',prior/'r133_acceptance.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def validate(path):
    v=load_prior();raw=path.read_bytes()
    with ZipFile(path) as z:
        infos=z.infolist();names=[i.filename for i in infos]
        if len(names)!=18 or len(set(names))!=18 or any(Path(n).name!=n or '\\' in n for n in names):raise ValueError('ZIP name/cardinality mismatch')
        if sum(i.file_size for i in infos)>2_000_000 or any(i.flag_bits&1 for i in infos):raise ValueError('ZIP size/encryption')
        if z.testzip() is not None:raise ValueError('ZIP CRC')
        j=lambda b:json.loads(b.decode('utf-8-sig'),object_pairs_hook=strict_pairs)
        r=j(z.read('R133_EVIDENCE.json'))
        for k in ('metadata_exit','unit_tests_exit','native_probe_exit'):
            if type(r.get(k)) is not int or r[k]!=0:raise ValueError('stage exit '+k)
        for k,n in [('listed_tests',16),('cases',2)]:
            if type(r.get(k)) is not int or r[k]!=n:raise ValueError('stage count '+k)
        if r.get('status')!='OWN_CHILD_HANDLE_LIFETIME_PASS_NOT_NETWORK_PROOF' or r.get('native_probe_requested') is not True:raise ValueError('status')
        for k in ('bfe_queried','kernel_origin_proof','network_owner_proof','canonical_file_identity_proof','pid_reuse_test_performed','no_direct_proof'):
            if r.get(k) is not False:raise ValueError('proof scope '+k)
        if r.get('source_blob_expected')!='32736365059885ed9137bd124edeecbc27c49446':raise ValueError('source blob')
        expected='2324c17e85826b72c9d2a93ec39cc5ba46b60187302da3d2bcf1ad691c5cad83'
        if r.get('source_sha256_expected')!=expected or r.get('source_sha256_observed')!=expected:raise ValueError('source hash')
        listed=re.findall(r'(?m)^([^\r\n]+): test\r?$',z.read('test-list.stdout.txt').decode())
        passed=re.findall(r'(?m)^test ([^\r\n ]+) \.\.\. ok\r?$',z.read('unit-tests.stdout.txt').decode())
        if len(listed)!=16 or len(set(listed))!=16 or sorted(listed)!=sorted(passed):raise ValueError('test names')
        if b'16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' not in z.read('unit-tests.stdout.txt'):raise ValueError('summary')
        if any(z.read(n).strip() for n in names if n.endswith('.stderr.txt')):raise ValueError('nonempty stderr')
        matrix=z.read('gate-matrix.stdout.txt').replace(b'\r\n',b'\n')
        if matrix!=v.o.matrix().encode('ascii') or r['gate_matrix_sha256']!=hashlib.sha256(matrix).hexdigest():raise ValueError('matrix differs from newly generated oracle')
        if z.read('process-lifetime.jsonl')!=z.read('process-lifetime.stdout.txt'):raise ValueError('raw log copies differ')
        rows=[j(line) for line in z.read('process-lifetime.jsonl').splitlines()]
        v.valid(rows,0)
        binaries={}
        for k in ('test_exe_sha256','inspector_sha256'):
            if not re.fullmatch('[0-9a-f]{64}',r.get(k,'')):raise ValueError('binary hash format')
            binaries[k]=r[k]
        return dict(schema=1,status='R133_RECEIVED_LOGS_VALIDATED_NOT_ALE_PROOF',
            source='owner-uploaded evidence-only(1).zip',archive_sha256=hashlib.sha256(raw).hexdigest(),
            members={n:dict(bytes=len(z.read(n)),sha256=hashlib.sha256(z.read(n)).hexdigest()) for n in sorted(names)},
            tests=16,matrix_states=60,matrix_sha256=hashlib.sha256(matrix).hexdigest(),
            cases=[dict(case=i,live_waits=[rows[2*i]['wait_before'],rows[2*i]['wait_after']],
                live_exit_code=rows[2*i]['get_exit_code'],terminated_wait=rows[2*i+1]['wait_result'],
                terminated_exit_code=rows[2*i+1]['get_exit_code'],same_pid_and_creation=True,
                secondary_matches=True,same_held_handles=True) for i in (0,1)],
            source_blob_reported=r['source_blob_expected'],source_sha256_reported=expected,
            windows_build_reported=r['windows_build'],rustc_version_reported=r['rustc_version'],
            binary_sha256_reported=binaries,binary_files_received=False,binaries_independently_rehashed=False,
            host_clock_attested=False,timestamps_used_as_authority=False,
            kernel_origin_proof=False,network_owner_proof=False,image_section_identity_proof=False,no_direct_proof=False)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('--output',type=Path);args=p.parse_args()
    result=validate(args.archive);text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if args.output:args.output.write_text(text,encoding='utf-8')
    print(text)
