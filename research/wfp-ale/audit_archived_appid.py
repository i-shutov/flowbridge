#!/usr/bin/env python3
"""Audit one already-completed Windows artifact. Offline; never runs a payload.

This is NOT a new Windows experiment or transferable G2 acceptance. The archive
pin came from the authenticated GitHub Actions artifact metadata. A broader
historical job used dynamic WFP filters; this auditor neither reruns that job
nor opens a socket, runs a binary, extracts executable files, or changes policy.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import struct
import sys
import zipfile

RUN_ID = 42339966586
JOB_ID = 128305303067
ARTIFACT_ID = 13560942739
HEAD_SHA = 'c339df2e4d20edf1d11d45786581a68451a71929'
MERGE_SHA = 'ab6ed5273db6e9741915a96c74809433af125870'
MAIN_SHA = '5b5afc2feeda2195f302380e615ba003d4906e09'
ARCHIVE_SHA256 = '95560460776b802da5ccd1a608495609715144a59a7fac5fbfaed331542faa92'
PAYLOAD_ZIP_SHA256 = 'a7320e2dce38c7e294a85492bb3a6ca4f2e8c28e68f4a12c7222724077a77be5'
AGENT_SHA256 = '8d682c9391c2d5e8241e97e6f028100e9c421d8ecd4bc0a6540e4ffb7e90a201'
PAYLOAD_NAME = 'FlowBridge-Rust-Candidate-Windows.zip'
DIAGNOSTIC_NAME = 'windows-wfp-dynamic-lifecycle.json'
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_JSON = 128 * 1024


class AuditError(ValueError):
    """Only constant error identifiers may reach stdout."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise AuditError(code)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def json_object(data: bytes) -> dict:
    require(len(data) <= MAX_JSON, 'json_size_limit')
    result = json.loads(data.decode('utf-8-sig'), object_pairs_hook=unique_object)
    require(type(result) is dict, 'json_object_required')
    return result


def check_zip(data: bytes) -> zipfile.ZipFile:
    archive = zipfile.ZipFile(io.BytesIO(data))
    try:
        entries = archive.infolist()
        require(0 < len(entries) <= 128, 'zip_entry_limit')
        require(len({e.filename for e in entries}) == len(entries), 'duplicate_zip_entry')
        require(sum(e.file_size for e in entries) <= MAX_EXPANDED, 'zip_expansion_limit')
        for entry in entries:
            p = PurePosixPath(entry.filename)
            require(not p.is_absolute() and '..' not in p.parts
                    and '\\' not in entry.filename and ':' not in entry.filename,
                    'unsafe_zip_name')
            require(not entry.flag_bits & 1, 'encrypted_zip_not_allowed')
        require(archive.testzip() is None, 'zip_crc_failed')
        return archive
    except Exception:
        archive.close()
        raise


def member(archive: zipfile.ZipFile, name: str) -> bytes:
    require(name in archive.namelist(), 'required_member_missing')
    return archive.read(name)


def verify_pe_x64(data: bytes) -> None:
    require(len(data) >= 64 and data[:2] == b'MZ', 'agent_not_pe')
    offset = struct.unpack_from('<I', data, 60)[0]
    require(offset >= 64 and offset + 26 <= len(data), 'invalid_pe_header')
    require(data[offset:offset + 4] == b'PE\0\0', 'invalid_pe_signature')
    require(struct.unpack_from('<H', data, offset + 4)[0] == 0x8664,
            'agent_not_x64')
    require(struct.unpack_from('<H', data, offset + 24)[0] == 0x20B,
            'agent_not_pe32_plus')


def evaluate_documents(verification: dict, manifest: dict, diagnostic: dict) -> dict:
    """Check evidence semantics separately from the pinned archive's integrity."""
    for document in (verification, manifest, diagnostic):
        require(document.get('source_commit') == MERGE_SHA, 'source_merge_mismatch')
        require(document.get('release_accepted') is False, 'release_flag_promoted')
    require(verification.get('pr_head_sha') == HEAD_SHA
            and manifest.get('pr_head_sha') == HEAD_SHA, 'source_head_mismatch')
    require(verification.get('passed') is True and diagnostic.get('passed') is True,
            'recorded_test_not_passed')
    require(verification.get('agent_sha256') == AGENT_SHA256
            and diagnostic.get('agent_sha256') == AGENT_SHA256
            and diagnostic.get('copied_client_sha256') == AGENT_SHA256,
            'recorded_binary_mismatch')
    require(manifest.get('schema') == 1
            and manifest.get('kind') == 'integration_candidate_NOT_RELEASE',
            'unexpected_manifest_kind')
    require(manifest.get('payload_sha256', {}).get('flowbridge-agent.exe') == AGENT_SHA256,
            'manifest_binary_mismatch')
    for key in ('legacy_cpp_wfp_helper_included', 'vendor_binary_included',
                'protected_mode_available', 'win10_11_accepted'):
        require(manifest.get(key) is False, 'manifest_safety_flag_promoted')
    for key in ('arbitrary_packet_pid_bound', 'crash_persistent_fail_closed',
                'dns_leak_free', 'win10_11_acceptance', 'ndisrd_modified'):
        require(diagnostic.get(key) is False, 'diagnostic_safety_flag_promoted')

    identity = diagnostic.get('app_id_lookup_consistency')
    require(type(identity) is dict, 'identity_result_missing')
    expected = {
        'selected_self_matches_target': True,
        'different_copy_self_matches_target': False,
        'agent_self_matches_target': False,
        'selected_running_image_equals_handle': False,
        'different_running_image_equals_handle': False,
        'selected_input_equals_handle_appid': False,
        'different_input_equals_handle_appid': False,
    }
    # Missing values and truthy 1/"false" cannot turn into observed booleans.
    for key, value in expected.items():
        require(identity.get(key) is value, 'pinned_identity_observation_mismatch')
    events = diagnostic.get('read_only_net_event_appid_correlation', {})
    require(events.get('query_succeeded') is True
            and events.get('active_qa_filter_verified') is True, 'event_query_unverified')
    require(events.get('event_appid_expected_source_identity_complete') is False,
            'event_identity_completion_promoted')
    require(events.get('kernel_packet_owner_bound') is False
            and events.get('release_accepted') is False, 'event_authority_promoted')

    return {
        'same_path_self_appid_equal': True,
        'identical_binary_different_path_appid_unequal': True,
        'input_vs_handle_canonical_appid_equal': False,
        'running_image_vs_handle_native_path_equal': False,
        'canonical_mapping_verdict': 'MISMATCH_OBSERVED_CAUSE_UNDETERMINED',
        'kernel_event_expected_identity_complete': False,
        # Test source uses different basenames in one directory; it is NOT R8.
        'same_basename_different_directories_measured': False,
        'hardlink_reparse_case_matrix_measured': False,
    }


def audit_bytes(data: bytes) -> dict:
    require(0 < len(data) <= MAX_ARCHIVE, 'archive_size_limit')
    require(digest(data) == ARCHIVE_SHA256, 'github_archive_digest_mismatch')
    with check_zip(data) as archive:
        raw_verification = member(archive, 'verification.json')
        raw_diagnostic = member(archive, DIAGNOSTIC_NAME)
        payload = member(archive, PAYLOAD_NAME)
        checksum = member(archive, PAYLOAD_NAME + '.sha256').decode('ascii').split()
        require(len(checksum) == 2 and checksum[0] == PAYLOAD_ZIP_SHA256
                and checksum[1] == PAYLOAD_NAME, 'payload_checksum_file_mismatch')
        require(digest(payload) == PAYLOAD_ZIP_SHA256, 'payload_zip_digest_mismatch')
        with check_zip(payload) as nested:
            manifest_bytes = member(nested, 'manifest.json')
            agent = member(nested, 'flowbridge-agent.exe')
            require(digest(agent) == AGENT_SHA256, 'agent_digest_mismatch')
            verify_pe_x64(agent)
            manifest = json_object(manifest_bytes)
            for name, expected in manifest.get('payload_sha256', {}).items():
                require(digest(member(nested, name)) == expected, 'payload_manifest_digest_mismatch')
        observations = evaluate_documents(json_object(raw_verification), manifest,
                                          json_object(raw_diagnostic))
    return {
        'ok': True,
        'evidence_kind': 'independent_offline_audit_of_historical_windows_artifact',
        'run_id': RUN_ID, 'job_id': JOB_ID, 'artifact_id': ARTIFACT_ID,
        'recorded_source_head': HEAD_SHA, 'recorded_test_merge': MERGE_SHA,
        'recorded_main_parent': MAIN_SHA,
        'archive_sha256': ARCHIVE_SHA256, 'payload_zip_sha256': PAYLOAD_ZIP_SHA256,
        'agent_sha256': AGENT_SHA256,
        'verification_json_sha256': digest(raw_verification),
        'diagnostic_json_sha256': digest(raw_diagnostic),
        'manifest_sha256': digest(manifest_bytes),
        'crc_and_nested_payload_hashes_verified': True, 'agent_pe_x64_verified': True,
        'historical_windows_appid_measurement_found': True,
        'historical_full_job_used_wfp_filters': True,
        'new_windows_execution': False, 'payload_executed_by_auditor': False,
        'wfp_filters_changed_by_auditor': False,
        'observations': observations,
        'historical_g1_acceptance_transferred': False,
        'research_head_native_acceptance': False, 'independent_native_reviewer_signoff': False,
        'kernel_process_epoch_proved': False,
        'ndisrd_packetbound_proved': False, 'system_no_direct_proved': False,
        'release_accepted': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    try:
        # Bounded even when a file grows during read.
        with args.archive.open('rb') as source:
            data = source.read(MAX_ARCHIVE + 1)
        report = audit_bytes(data)
    except AuditError as error:
        report = {'ok': False, 'error': str(error), 'release_accepted': False}
    except Exception:
        report = {'ok': False, 'error': 'archive_audit_failed', 'release_accepted': False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['ok'] else 2


if __name__ == '__main__':
    sys.exit(main())
