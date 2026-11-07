#!/usr/bin/env python3
"""Independent offline verification of read-only Windows Rust+ctypes WFP AppId.

Does not execute Rust, Windows, drivers, filters, network or arbitrary programs.
"""
from __future__ import annotations
import hashlib, io, json, zipfile, sys
from pathlib import Path

RUN=42366954519
JOB=128386911960
ARTIFACT=13571679812
COMMIT='c2c2f8572e20979d6aeec8a0116f27bdfd6dbd9e'
DIGEST='83f6dbbacef09ad6bd0d30ce3fb0fece7864566c6329647ffa8cb47b8c298b13'
SOURCES={
 'appid_native_matrix.py':('9421be67d5fd977ceab334830be2cc83b4135c27','d1a4050c18f144ca5072440e5804bc685066c950dc485f46f3c643283bdd9ba9'),
 'appid_readonly.rs':('1f71e0a85960bbab66b560dbf91849d838fdaffd','72da2eeb6fd53f2d57e3752c663859916589a235687b5729dcf7b75d9f94b445'),
}
EXPECTED=['same_file','same_name_different_directory','hardlink','symlink','case_variant']
EQUAL=[True,False,False,True,True]

class Rejected(ValueError): pass

def demand(cond,reason):
 if not cond: raise Rejected(reason)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def blob(raw): return hashlib.sha1(f'blob {len(raw)}\0'.encode()+raw).hexdigest()

def strict(pairs):
 d={}
 for k,v in pairs:
  demand(k not in d,'duplicate_json_key');d[k]=v
 return d

def exact(d,fields):
 demand(type(d) is dict and set(d)==set(fields),'unexpected_or_missing_fields')

def boolean(d,k,value): demand(d.get(k) is value,f'{k}_mismatch')

def validate(record):
 exact(record,['driver_or_filter_changed','evidence_level','independent_native_acceptance',
               'kernel_process_epoch_proved','native_api_reads','native_measurement_complete',
               'native_windows_wfp_appid_read','no_direct_proved','ok','optional_aliases_skipped',
               'release_accepted','rust_crosscheck_kind','rust_pairwise_crosscheck_complete',
               'rust_probe_built_and_executed','source_sha256','temporary_files_removed',
               'transparent_packet_owner_proved','comparisons','netsh_readonly'])
 for key in ('ok','native_measurement_complete','native_windows_wfp_appid_read',
             'rust_probe_built_and_executed','rust_pairwise_crosscheck_complete',
             'temporary_files_removed'):boolean(record,key,True)
 for key in ('release_accepted','driver_or_filter_changed','independent_native_acceptance',
             'kernel_process_epoch_proved','transparent_packet_owner_proved','no_direct_proved'):
  boolean(record,key,False)
 demand(record['evidence_level']=='native_api_plus_rust_pairwise','incorrect_evidence_class')
 demand(record['rust_crosscheck_kind']=='equality_and_lengths_only','incorrect_crosscheck_claim')
 demand(record['native_api_reads']==10 and type(record['native_api_reads']) is int,'unexpected_native_reads')
 demand(record['optional_aliases_skipped']=={},'untested_optional_alias')
 demand(type(record['comparisons']) is list and len(record['comparisons'])==5,'missing_comparisons')
 for i,(row,case,equal) in enumerate(zip(record['comparisons'],EXPECTED,EQUAL)):
  exact(row,['appid_equal','case','rust_and_ctypes_agree'])
  demand(row['case']==case,'case_mismatch')
  boolean(row,'appid_equal',equal)
  boolean(row,'rust_and_ctypes_agree',True)
 demand(type(record['netsh_readonly']) is list and len(record['netsh_readonly'])==2,'netsh_evidence_invalid')
 for row in record['netsh_readonly']:
  exact(row,['available','successful','mentions_device_path'])
  for key in row:boolean(row,key,True)
 exact(record['source_sha256'],SOURCES.keys())
 for name,(gitsha,winsha) in SOURCES.items():
  demand(record['source_sha256'][name]==winsha,'unexpected_source_sha')
 return {
  'ok':True, 'evidence_class':'real_windows_readonly_rust_and_ctypes_appid',
  'run_id':RUN, 'job_id':JOB, 'artifact_id':ARTIFACT, 'source_commit':COMMIT,
  'rust_built_and_executed':True, 'windows_native_api_reads':10,
  'independent_ffi_equivalence_and_length_checks':5,
  'same_basename_different_path_appid_unequal':True,
  'hardlink_same_file_id_different_appid':False,
  'hardlink_input_appid_unequal':True,
  'symlink_appid_equal':True,
  'case_fold_appid_equal':True,
  'netsh_native_device_path_observed':True,
  'full_appid_bytes_crosschecked_by_rust':False,
  'driver_or_filter_changed':False,
  'kernel_owner_or_packetbound_proved':False,
  'release_accepted':False,
 }

def verify_archive(archive,paths):
 demand(sha(archive)==DIGEST,'artifact_digest_mismatch')
 for name,(gitsha,winsha) in SOURCES.items():
  raw=paths[name]
  demand(blob(raw)==gitsha,'source_git_blob_mismatch')
  demand(sha(raw.replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))==winsha,'windows_checkout_digest_mismatch')
 with zipfile.ZipFile(io.BytesIO(archive)) as z:
  demand(z.namelist()==['native-result.json'],'unexpected_archive_contents')
  demand(z.testzip() is None,'zip_crc_failed')
  raw=z.read('native-result.json')
  demand(len(raw)<65536,'oversized_payload')
 return {**validate(json.loads(raw.decode('utf-8-sig'),object_pairs_hook=strict)),
         'artifact_sha256':DIGEST,'source_git_blobs_match':True,'no_binary_executed_by_verifier':True}

def main():
 from argparse import ArgumentParser
 p=ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('source_dir',type=Path);args=p.parse_args()
 try:
  result=verify_archive(args.archive.read_bytes(),{k:(args.source_dir/k).read_bytes() for k in SOURCES})
 except Rejected as e:result={'ok':False,'reason':str(e),'release_accepted':False}
 except Exception:result={'ok':False,'reason':'invalid_archive_or_sources','release_accepted':False}
 print(json.dumps(result,sort_keys=True,indent=2));return 0 if result['ok'] else 2
if __name__=='__main__':sys.exit(main())
