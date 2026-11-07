"""Separate negative verification for exact historical WFP AppId evidence.

These synthetic mutations check the audit gate; the genuine original archive
is checked separately and is never edited or used to execute its PE payloads.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import unittest
import zipfile
import io

import appid_event_correlation as m

ARTIFACT=Path(os.environ['FLOWBRIDGE_R10_ARCHIVE']) if os.environ.get('FLOWBRIDGE_R10_ARCHIVE') else Path(__file__).parents[3]/'flowbridge-existing-windows-evidence-c339df2e.zip'


def baseline():
    with zipfile.ZipFile(ARTIFACT) as z:
        return json.loads(z.read('windows-wfp-dynamic-lifecycle.json'))

class Audit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ARTIFACT.is_file():
            raise unittest.SkipTest('pinned historical Windows archive not present; no native claim')
        cls.original = baseline()

    def test_actual_archive_provenance_and_observations(self):
        result=m.run_on_archive(ARTIFACT.read_bytes())
        self.assertEqual(result['evidence_kind'],'audited_historical_windows_exact_filter_events')
        self.assertTrue(result['observations']['path_spelling_canonicalization_discrepancy'])
        self.assertFalse(result['observations']['exact_per_event_source_partition_verified'])
        self.assertFalse(result['release_accepted'])

    def test_pristine_redacted_record(self):
        self.assertEqual(m.evaluate_exact_filter_events(self.original)['exact_filter_event_count'],3)

    def test_forged_or_missing_filter_event(self):
        for key,val in [
            ('exact_qa_filter_classify_drops',0),
            ('exact_qa_filter_classify_drops',1),
            ('exact_qa_filter_classify_drops',True),
            ('active_qa_filter_verified',False),
            ('query_succeeded',False),
            ('event_collection_proven',False),
            ('exact_filter_events_without_appid',1),
            ('unrelated_filter_classify_drops_same_port',1)]:
            with self.subTest(key=key,val=val):
                data=deepcopy(self.original)
                data['read_only_net_event_appid_correlation'][key]=val
                with self.assertRaises(m.EvidenceMismatch):
                    m.evaluate_exact_filter_events(data)

    def test_canonical_handle_count_cannot_be_erased_or_promoted(self):
        for key in ('selected_canonical_handle_appid_event_matches','other_canonical_handle_appid_event_matches',
                    'selected_native_handle_path_event_matches','other_native_handle_path_event_matches'):
            data=deepcopy(self.original)
            data['read_only_net_event_appid_correlation'][key]=0
            with self.assertRaisesRegex(m.EvidenceMismatch,'count_'):
                m.evaluate_exact_filter_events(data)

    def test_input_path_discrepancy_stays_visible(self):
        for key in ('selected_event_appid_matches','other_event_appid_matches'):
            data=deepcopy(self.original)
            data['read_only_net_event_appid_correlation'][key]=1
            with self.assertRaisesRegex(m.EvidenceMismatch,'count_'):
                m.evaluate_exact_filter_events(data)

    def test_cannot_promote_identity_flag_or_kernel_proof(self):
        for field in ('event_appid_expected_source_identity_complete','kernel_packet_owner_bound','release_accepted'):
            data=deepcopy(self.original)
            data['read_only_net_event_appid_correlation'][field]=True
            with self.assertRaises(m.EvidenceMismatch):
                m.evaluate_exact_filter_events(data)

    def test_cannot_claim_appid_scoping_without_negative_controls(self):
        data=deepcopy(self.original)
        data['app_id_only_trial']['different_executable_allowed']=False
        with self.assertRaises(m.EvidenceMismatch):
            m.evaluate_exact_filter_events(data)
        data=deepcopy(self.original)
        data['port_only_trial']['different_executable_allowed']=True
        with self.assertRaises(m.EvidenceMismatch):
            m.evaluate_exact_filter_events(data)

    def test_archive_mutation_rejected_by_sha(self):
        raw=bytearray(ARTIFACT.read_bytes())
        raw[31]^=1
        with self.assertRaises(Exception):
            m.run_on_archive(bytes(raw))

    def test_non_integer_counter_does_not_pass(self):
        for val in (True,'3',3.0,None):
            data=deepcopy(self.original)
            data['read_only_net_event_appid_correlation']['exact_qa_filter_classify_drops']=val
            with self.assertRaises(m.EvidenceMismatch):
                m.evaluate_exact_filter_events(data)

    def test_historical_not_per_event_or_research_head_acceptance(self):
        observation=m.evaluate_exact_filter_events(self.original)
        for field in ('exact_per_event_source_partition_verified','same_basename_different_dirs_measured',
                      'process_epoch_bound_to_event','packet_pid_bound','native_research_sha_executed','release_accepted'):
            self.assertIs(observation[field],False)

if __name__=='__main__':
    unittest.main(verbosity=2)
