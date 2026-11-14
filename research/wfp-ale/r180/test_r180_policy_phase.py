"""R180: fast deterministic negative/guard tests. Standard-library only."""
import unittest
import r180_policy_phase_matrix as m

class PhaseContractTests(unittest.TestCase):
    def test_matrix_count_and_two_families(self):
        data=list(m.rows())
        self.assertEqual(len(data),2048)
        self.assertEqual(set(x['family'] for x in data),{4,6})

    def test_honor_only_before_effective_redirect_must_not_attest(self):
        for family in (4,6):
            self.assertEqual(m.source_result('policy_honor_original',m.HONOR,'selected',
                   'selected',True,True,True,family),'SOURCE_BLOCK_REQUEST')

    def test_honor_bit_veto_even_if_contradictory_redirect_bit_set(self):
        for family in (4,6):
            self.assertEqual(m.source_result('redirected_loopback',m.HONOR|m.REDIRECTED,
                  'selected','selected',True,True,True,family),'SOURCE_BLOCK_REQUEST')

    def test_proxy_record_flag_is_not_leg_certificate(self):
        for family in (4,6):
            # R19 does not inspect PROXY; synthetic flags R|P reach an AUTH candidate
            # on loopback only, even though their native coexistence is not proven.
            self.assertEqual(m.source_result('redirected_loopback',m.REDIRECTED|m.PROXY,
                  'selected','selected',True,True,True,family),'ATTEST_CANDIDATE_ONLY')
            self.assertEqual(m.source_result('record_tagged_ssh',m.REDIRECTED|m.PROXY,
                  'selected','selected',True,True,True,family),'SOURCE_BLOCK_REQUEST')

    def test_dead_owner_or_missing_metadata_prohibits_attestation(self):
        for family in (4,6):
            for owner,meta in (('broker',True),('selected',False)):
                self.assertEqual(m.source_result('redirected_loopback',m.REDIRECTED,
                      'selected',owner,meta,True,True,family),'SOURCE_BLOCK_REQUEST')

    def test_sibling_direct_and_reauthorization_cannot_attest(self):
        for family in (4,6):
            for stage,flags in [('sibling_direct',m.REDIRECTED),
                                ('redirected_loopback',m.REDIRECTED|m.REAUTH)]:
                self.assertEqual(m.source_result(stage,flags,'selected','selected',
                         True,True,True,family),'SOURCE_BLOCK_REQUEST')

if __name__=='__main__': unittest.main()
