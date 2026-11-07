#!/usr/bin/env python3
"""Independent pinned archival verifier of *one completed* Windows WFP AppId test.

No Windows API, driver, network, executable execution or zip extraction.
This verdict never constitutes packet-owner attribution or release acceptance.
"""
from __future__ import annotations
import hashlib
import io
import json
import sys
from pathlib import Path
from zipfile import ZipFile

EXPECTED_ARCHIVE_SHA256 = '6565405ee70224c74611e3d186be7ee873361aeab22d3b3f2629b65f1b4aaf9a'
EXPECTED_SOURCE_GIT_BLOB = '2132bf55cedc062739a5b8b96200a17352fa2898'
EXPECTED_SOURCE_CHECKOUT_SHA256 = '15b3b9335b5cc289ff0c440a59221495486c97b8514e85c1369cafb988700469'
EXPECTED_COMMIT = 'c6a1884a4300121f91dbb14c9f9eb9c64de944c3'
EXPECTED_RUN = 42362494488
EXPECTED_JOB = 128373613085
EXPECTED_ARTIFACT = 13569289892
EXPECTED_ORDER = ['same_file', 'same_name_different_directory', 'hardlink', 'symlink', 'case_variant']
EXPECTED_COMPARISONS = [True, False, False, True, True]

class RejectedEvidence(ValueError):
    pass

def insist(condition: bool, code: str):
    if not condition:
        raise RejectedEvidence(code)

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f'blob {len(data)}\0'.encode('ascii') + data).hexdigest()

def audit_record(record: dict) -> dict:
    insist(type(record) is dict, 'root_not_object')
    required = {
        'ok': True,
        'evidence_level': 'native_readonly_appid_path_diagnostic',
        'kernel_pid_epoch_bound': False,
        'ndisrd_packetbound': False,
        'system_no_direct': False,
        'release_accepted': False,
        'temporary_files_removed': True,
        'source_sha256': EXPECTED_SOURCE_CHECKOUT_SHA256,
    }
    for key, value in required.items():
        insist(record.get(key) == value and type(record.get(key)) is type(value),
               'field_' + key + '_mismatch')
    insist(record.get('skips') == {}, 'optional_cases_skipped')
    cases=record.get('cases')
    insist(type(cases) is list and len(cases)==5, 'incomplete_case_matrix')
    for i, (case, name, expected) in enumerate(zip(cases, EXPECTED_ORDER, EXPECTED_COMPARISONS)):
        insist(case.get('case') == name, f'case_{i}_name_mismatch')
        insist(case.get('supplied_pair_appid_equal') is expected, f'case_{i}_pair_mismatch')
        for side in ('first','second'):
            obj=case.get(side)
            insist(type(obj) is dict, f'case_{i}_{side}_not_object')
            for key,val in {
                'resolved_appid_is_handle_device_path': True,
                'resolved_appid_utf16_device_path': True,
                'supplied_appid_is_handle_device_path': False,
                'supplied_appid_utf16_device_path': True,
                'supplied_vs_resolved_appid_equal': False,
            }.items():
                insist(obj.get(key) is val, f'case_{i}_{side}_{key}_mismatch')
            insist(set(obj)=={
                'resolved_appid_is_handle_device_path','resolved_appid_utf16_device_path',
                'supplied_appid_is_handle_device_path','supplied_appid_utf16_device_path',
                'supplied_vs_resolved_appid_equal'},'unexpected_sensitive_or_unverified_field')
    return {
        'actual_native_windows_API_execution_proved': True,
        'native_appid_cases_measured': len(cases),
        'same_path_appid_equal': True,
        'same_basename_different_directory_appid_equal': False,
        'hardlink_alias_appid_equal': False,
        'symlink_directory_appid_equal': True,
        'case_variant_appid_equal': True,
        'input_vs_handle_resolved_appid_equal_in_all_cases': False,
        'handle_resolved_appid_matches_nt_handle_device_path_in_all_cases': True,
        'process_epoch_bound': False,
        'kernel_connection_owner_bound': False,
        'packetbound_or_no_direct_proved': False,
    }

def audit(archive_bytes:bytes, source_bytes:bytes) -> dict:
    insist(sha256(archive_bytes)==EXPECTED_ARCHIVE_SHA256, 'github_artifact_digest_mismatch')
    insist(git_blob_sha1(source_bytes)==EXPECTED_SOURCE_GIT_BLOB,'git_source_blob_mismatch')
    windows_checkout=source_bytes.replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')
    insist(sha256(windows_checkout)==EXPECTED_SOURCE_CHECKOUT_SHA256,'windows_source_sha_mismatch')
    with ZipFile(io.BytesIO(archive_bytes)) as archive:
        insist(archive.testzip() is None,'zip_crc_failure')
        insist(archive.namelist()==['native-result.json'],'zip_member_mismatch')
        raw=archive.read('native-result.json')
    def unique(pairs):
        out={}
        for k,v in pairs:
            insist(k not in out,'duplicate_json_field')
            out[k]=v
        return out
    record=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique)
    findings=audit_record(record)
    return {
        'ok':True,'status':'PINNED_NATIVE_APPID_MEASUREMENT_ACCEPTED_ONLY',
        'run_id':EXPECTED_RUN,'job_id':EXPECTED_JOB,'artifact_id':EXPECTED_ARTIFACT,
        'source_commit_sha':EXPECTED_COMMIT,
        'github_artifact_sha256':EXPECTED_ARCHIVE_SHA256,
        'git_blob_sha':EXPECTED_SOURCE_GIT_BLOB,
        'windows_checkout_sha256':EXPECTED_SOURCE_CHECKOUT_SHA256,
        'windows_checkout_line_endings':'CRLF',
        'native_findings':findings,
        'driver_or_filter_installed_by_experiment':False,
        'release_accepted':False,
        'g2_packetbound_pass':False,
    }

def main()->int:
    if len(sys.argv) not in (1,3):
        print('usage: verify_native_r12.py [artifact.zip handle_appid_probe.py]',file=sys.stderr)
        return 2
    root=Path(__file__).resolve().parent
    artifact=Path(sys.argv[1]) if len(sys.argv)==3 else root/'fixtures/r12-native-windows.zip'
    source=Path(sys.argv[2]) if len(sys.argv)==3 else root/'handle_appid_probe.py'
    try:
        result=audit(artifact.read_bytes(),source.read_bytes())
    except Exception as error:
        code=str(error) if isinstance(error,RejectedEvidence) else 'input_or_validation_error'
        result={'ok':False,'error':code,'release_accepted':False}
    print(json.dumps(result,sort_keys=True,indent=2))
    return 0 if result['ok'] else 2
if __name__=='__main__':
    raise SystemExit(main())
