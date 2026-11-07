#!/usr/bin/env python3
"""Offline independent verification of one *real* GitHub-hosted Windows AppId run.

Reads exact pinned GitHub artifact ZIP and source bytes; no Windows API,
no executable/driver/filter/network, no extraction and no release promotion.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

COMMIT = '4562aad02b1eac48f8dd87783527534a2806373c'
RUN = 42366194426
JOB = 128384679860
ARTIFACT = 13572085662
GITHUB_SHA256 = '8e58b08abf79fc70bfea5c8dbf7046bc5719dc43ebf85c9b5450b676e3e87d40'
ORIGINAL_SOURCE_BLOB = 'e7a25523868241efa71a649b9528908b1cba1033'
CHECKOUT_SHA256 = '4ef5d70115b672f615ecf418572b243390cd4a97fb808f43c6e98e6a8ecbbb3e'
CASE_ORDER = ['same_file', 'same_name_different_directory', 'hardlink', 'symlink', 'case_variant']
APPID_EQUAL = [True, False, False, True, True]
PHYSICAL_SAME = [True, False, True, True, True]

class EvidenceRejected(ValueError):
    pass

def require(ok: bool, reason: str) -> None:
    if not ok:
        raise EvidenceRejected(reason)

def raw_sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(f'blob {len(raw)}\0'.encode('ascii') + raw).hexdigest()

def strict_obj(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for k,v in pairs:
        require(k not in result,'duplicate_json_field')
        result[k] = v
    return result

def require_exact_keys(data: dict, required: list[str] | set[str], name: str) -> None:
    require(type(data) is dict and set(data) == set(required), f'{name}_schema_mismatch')

def flag(data: dict, name: str, expected: bool) -> None:
    require(data.get(name) is expected, f'{name}_false_verdict')

def check_shape(shape: dict) -> None:
    require_exact_keys(shape,['both_decoded','exact_equal','same_prefix_volume_shape',
                             'component_mismatch_count','short_name_divergence'],'path_shape')
    flag(shape,'both_decoded',True)
    flag(shape,'same_prefix_volume_shape',True)
    require(type(shape['component_mismatch_count']) is int and 0 <= shape['component_mismatch_count'] <= 2,
            'path_component_mismatch_count_invalid')
    require(type(shape['short_name_divergence']) is bool,'path_shortname_flag_invalid')
    require(type(shape['exact_equal']) is bool,'path_exact_flag_invalid')

def check_half(side: dict, name: str, symlink: bool) -> None:
    expected=['supplied_matches_handle_appid','expanded_matches_handle_appid',
              'supplied_matches_expanded_appid','supplied_matches_lexical_device_path',
              'handle_matches_handle_nt_device_path','expanded_matches_handle_nt_device_path',
              'long_dos_path_changed','contains_8dot3_short_component',
              'input_vs_handle_structure','input_vs_expanded_structure']
    require_exact_keys(side, expected, name)
    flag(side,'supplied_matches_handle_appid',False)
    flag(side,'handle_matches_handle_nt_device_path',True)
    flag(side,'long_dos_path_changed',True)
    flag(side,'contains_8dot3_short_component',True)
    flag(side,'expanded_matches_handle_appid',not symlink)
    flag(side,'expanded_matches_handle_nt_device_path',not symlink)
    flag(side,'supplied_matches_expanded_appid',symlink)
    flag(side,'supplied_matches_lexical_device_path',not symlink)
    check_shape(side['input_vs_handle_structure'])
    check_shape(side['input_vs_expanded_structure'])
    a=side['input_vs_handle_structure']; b=side['input_vs_expanded_structure']
    flag(a,'exact_equal',False)
    flag(a,'short_name_divergence',True)
    require(a['component_mismatch_count']==1,'observed_handle_difference_not_one_component')
    flag(b,'exact_equal',symlink)
    flag(b,'short_name_divergence',not symlink)
    require(b['component_mismatch_count'] == (0 if symlink else 1), 'expansion_discrepancy_mismatched')

def verify_record(data: dict) -> dict:
    require_exact_keys(data,['ok','evidence_level','fixture_cleanup_complete','kernel_owner_proved',
            'native_windows_called','ndisrd_packetbound_proved','release_accepted',
            'skipped_optional_aliases','source_sha256','system_no_direct_proved',
            'wfp_driver_or_filter_modified','cases'], 'root')
    flag(data,'ok',True)
    flag(data,'native_windows_called',True)
    flag(data,'fixture_cleanup_complete',True)
    for k in ('kernel_owner_proved','ndisrd_packetbound_proved','release_accepted',
              'system_no_direct_proved','wfp_driver_or_filter_modified'):
        flag(data,k,False)
    require(data['evidence_level']=='native_readonly_namespace_and_fileid_observation',
            'incorrect_evidence_level')
    require(data['source_sha256']==CHECKOUT_SHA256,'source_sha_mismatch')
    require(data['skipped_optional_aliases']=={},'optional_alias_missing')
    require(type(data['cases']) is list and len(data['cases'])==5,'case_count_invalid')
    for i,(case,name,same_id,same_appid) in enumerate(zip(data['cases'],CASE_ORDER,PHYSICAL_SAME,APPID_EQUAL)):
        require_exact_keys(case,['case','same_physical_file_by_volume_file_index',
                                 'same_supplied_appid','left','right'],f'case_{i}')
        require(case['case']==name,'case_order_invalid')
        flag(case,'same_physical_file_by_volume_file_index',same_id)
        flag(case,'same_supplied_appid',same_appid)
        check_half(case['left'],f'{name}_left',False)
        check_half(case['right'],f'{name}_right',name=='symlink')
    require(data['cases'][0]['left']==data['cases'][0]['right'],'same_file_inconsistent_details')
    return {
        'ok':True, 'evidence_kind':'real_windows_readonly_appid_namespace_and_file_id',
        'case_count':5,
        'short_8dot3_mismatch_component_confirmed':True,
        'input_appid_equals_lexical_querydosdevice_device_path_except_symlink':True,
        'getlongpathname_corrects_input_appid_to_handle_appid_for_non_symlink':True,
        'getlongpathname_not_enough_for_directory_symlink':True,
        'file_id_distinct_for_copies':True,
        'hardlink_same_file_id_but_distinct_appid':True,
        'symlink_same_file_id_same_input_appid':True,
        'no_kernel_owner_or_ndisrd_packetbound_or_system_direct_proof':True,
        'native_windows_10_11_tested':False,
        'release_accepted':False,
    }

def verify_archive(raw: bytes, original_source: bytes) -> dict:
    require(raw_sha(raw)==GITHUB_SHA256, 'github_artifact_digest_mismatch')
    require(git_blob_sha(original_source)==ORIGINAL_SOURCE_BLOB, 'source_git_blob_mismatch')
    require(raw_sha(original_source.replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))==CHECKOUT_SHA256,
            'checkout_line_endings_digest_mismatch')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(z.namelist()==['native-result.json'],'unexpected_artifact_files')
        require(z.testzip() is None, 'zip_crc_failed')
        payload=z.read('native-result.json')
        require(len(payload)<65536,'oversized_redacted_result')
    data=json.loads(payload.decode('utf-8-sig'),object_pairs_hook=strict_obj)
    summary=verify_record(data)
    return {
        **summary,
        'research_source_commit':COMMIT,
        'run_id':RUN,
        'windows_job_id':JOB,
        'artifact_id':ARTIFACT,
        'github_artifact_sha256':GITHUB_SHA256,
        'original_source_git_blob_sha1':ORIGINAL_SOURCE_BLOB,
        'observed_windows_checkout_sha256':CHECKOUT_SHA256,
        'raw_paths_or_appids_exported':False,
        'driver_or_filter_changed_by_this_run':False,
    }

def main() -> int:
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive',type=Path)
    p.add_argument('source',type=Path)
    ns=p.parse_args()
    try:
        raw=ns.archive.read_bytes()
        source=ns.source.read_bytes()
        result=verify_archive(raw,source)
    except EvidenceRejected as err:
        result={'ok':False,'reason':str(err),'release_accepted':False}
    except Exception:
        result={'ok':False,'reason':'archive_or_source_invalid','release_accepted':False}
    print(json.dumps(result,sort_keys=True,indent=2))
    return 0 if result['ok'] else 2

if __name__=='__main__':
    raise SystemExit(main())
