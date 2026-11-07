"""Independent reader-contract tests; synthetic documents are NOT native proof."""
import copy
import io
import json
import struct
import unittest
import zipfile

import audit_archived_appid as a


def fixture():
    v = dict(source_commit=a.MERGE_SHA, pr_head_sha=a.HEAD_SHA,
             release_accepted=False, passed=True, agent_sha256=a.AGENT_SHA256)
    m = dict(source_commit=a.MERGE_SHA, pr_head_sha=a.HEAD_SHA,
             release_accepted=False, schema=1, kind='integration_candidate_NOT_RELEASE',
             payload_sha256={'flowbridge-agent.exe': a.AGENT_SHA256},
             legacy_cpp_wfp_helper_included=False, vendor_binary_included=False,
             protected_mode_available=False, win10_11_accepted=False)
    d = dict(source_commit=a.MERGE_SHA, release_accepted=False, passed=True,
             agent_sha256=a.AGENT_SHA256, copied_client_sha256=a.AGENT_SHA256,
             arbitrary_packet_pid_bound=False, crash_persistent_fail_closed=False,
             dns_leak_free=False, win10_11_acceptance=False, ndisrd_modified=False,
             app_id_lookup_consistency={
                 'selected_self_matches_target': True,
                 'different_copy_self_matches_target': False,
                 'agent_self_matches_target': False,
                 'selected_running_image_equals_handle': False,
                 'different_running_image_equals_handle': False,
                 'selected_input_equals_handle_appid': False,
                 'different_input_equals_handle_appid': False},
             read_only_net_event_appid_correlation={
                 'query_succeeded': True, 'active_qa_filter_verified': True,
                 'event_appid_expected_source_identity_complete': False,
                 'kernel_packet_owner_bound': False, 'release_accepted': False})
    return v, m, d


class EvidenceReaderContract(unittest.TestCase):
    def test_canonical_negative_is_not_flattened_into_pass(self):
        out = a.evaluate_documents(*fixture())
        self.assertEqual(out['canonical_mapping_verdict'], 'MISMATCH_OBSERVED_CAUSE_UNDETERMINED')
        self.assertFalse(out['input_vs_handle_canonical_appid_equal'])
        self.assertFalse(out['kernel_event_expected_identity_complete'])

    def test_same_basename_and_aliases_are_not_invented(self):
        out = a.evaluate_documents(*fixture())
        self.assertFalse(out['same_basename_different_directories_measured'])
        self.assertFalse(out['hardlink_reparse_case_matrix_measured'])

    def test_all_three_source_shas_are_checked(self):
        for position in range(3):
            with self.subTest(position=position):
                docs = list(fixture()); docs[position]['source_commit'] = 'f' * 40
                with self.assertRaisesRegex(a.AuditError, 'source_merge_mismatch'):
                    a.evaluate_documents(*docs)

    def test_merge_and_pr_head_are_not_interchangeable(self):
        v, m, d = fixture(); v['pr_head_sha'] = a.MERGE_SHA
        with self.assertRaisesRegex(a.AuditError, 'source_head_mismatch'):
            a.evaluate_documents(v, m, d)

    def test_all_release_flags_stay_explicit_false(self):
        for position in range(3):
            for value in (True, 0, None, 'false'):
                with self.subTest(position=position, value=value):
                    docs = list(fixture()); docs[position]['release_accepted'] = value
                    with self.assertRaisesRegex(a.AuditError, 'release_flag_promoted'):
                        a.evaluate_documents(*docs)

    def test_generic_pass_not_sufficient_without_observations(self):
        v, m, d = fixture(); del d['app_id_lookup_consistency']
        with self.assertRaisesRegex(a.AuditError, 'identity_result_missing'):
            a.evaluate_documents(v, m, d)

    def test_missing_false_not_treated_as_false(self):
        v, m, d = fixture(); del d['app_id_lookup_consistency']['selected_input_equals_handle_appid']
        with self.assertRaisesRegex(a.AuditError, 'pinned_identity_observation_mismatch'):
            a.evaluate_documents(v, m, d)

    def test_integer_and_string_booleans_rejected(self):
        for value in (0, 1, 'true', 'false'):
            v, m, d = fixture()
            d['app_id_lookup_consistency']['selected_input_equals_handle_appid'] = value
            with self.assertRaisesRegex(a.AuditError, 'pinned_identity_observation_mismatch'):
                a.evaluate_documents(v, m, d)

    def test_false_canonical_result_cannot_be_overwritten_with_true(self):
        v, m, d = fixture()
        d['app_id_lookup_consistency']['selected_input_equals_handle_appid'] = True
        with self.assertRaisesRegex(a.AuditError, 'pinned_identity_observation_mismatch'):
            a.evaluate_documents(v, m, d)

    def test_different_binary_rejected(self):
        v, m, d = fixture(); d['copied_client_sha256'] = '0' * 64
        with self.assertRaisesRegex(a.AuditError, 'recorded_binary_mismatch'):
            a.evaluate_documents(v, m, d)

    def test_manifest_hash_must_agree(self):
        v, m, d = fixture(); m['payload_sha256']['flowbridge-agent.exe'] = '0' * 64
        with self.assertRaisesRegex(a.AuditError, 'manifest_binary_mismatch'):
            a.evaluate_documents(v, m, d)

    def test_kernel_proof_promotion_rejected(self):
        v, m, d = fixture(); d['arbitrary_packet_pid_bound'] = True
        with self.assertRaisesRegex(a.AuditError, 'diagnostic_safety_flag_promoted'):
            a.evaluate_documents(v, m, d)

    def test_incomplete_event_identity_must_remain_incomplete(self):
        v, m, d = fixture()
        d['read_only_net_event_appid_correlation']['event_appid_expected_source_identity_complete'] = True
        with self.assertRaisesRegex(a.AuditError, 'event_identity_completion_promoted'):
            a.evaluate_documents(v, m, d)

    def test_unknown_archive_fails_before_parse(self):
        with self.assertRaisesRegex(a.AuditError, 'github_archive_digest_mismatch'):
            a.audit_bytes(b'not the pinned archive')

    def test_oversized_archive_rejected_before_parse(self):
        with self.assertRaisesRegex(a.AuditError, 'archive_size_limit'):
            a.audit_bytes(b'x' * (a.MAX_ARCHIVE + 1))

    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(a.AuditError, 'duplicate_json_key'):
            a.json_object(b'{"release_accepted":false,"release_accepted":true}')

    def test_unsafe_archive_paths_rejected_without_extraction(self):
        for name in ('../escape.exe', '/escape.exe', r'C:\escape.exe'):
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as z: z.writestr(name, b'unexecuted')
            with self.assertRaisesRegex(a.AuditError, 'unsafe_zip_name'):
                a.check_zip(data.getvalue())

    def test_non_pe_is_rejected(self):
        with self.assertRaisesRegex(a.AuditError, 'agent_not_pe'):
            a.verify_pe_x64(b'ELF' * 64)

    def test_pe_machine_and_optional_header_checked(self):
        data = bytearray(256); data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 64)
        data[64:68] = b'PE\0\0'
        struct.pack_into('<H', data, 68, 0x8664)
        struct.pack_into('<H', data, 88, 0x20B)
        a.verify_pe_x64(bytes(data))
        struct.pack_into('<H', data, 68, 0x14c)
        with self.assertRaisesRegex(a.AuditError, 'agent_not_x64'):
            a.verify_pe_x64(bytes(data))


if __name__ == '__main__':
    unittest.main(verbosity=2)
