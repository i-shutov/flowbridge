import unittest
from r185_callout_fate import matrix, classify, canonical


class FallbackBoundaryTests(unittest.TestCase):
    def test_exhaustive_cardinality(self):
        self.assertEqual(len(list(matrix())), 256)

    def test_exact_r19_missing_callout_blocks_at_filter(self):
        for family in ('v4', 'v6'):
            for kind in ('redirect', 'auth'):
                self.assertEqual(classify(family,True,True,True,True,False,kind,False),
                                 'FILTER_TREATED_AS_BLOCK')

    def test_registered_never_conflated_with_permitted(self):
        for family in ('v4', 'v6'):
            for kind in ('redirect','auth'):
                self.assertEqual(classify(family,True,True,True,True,True,kind,False),
                                 'CALLOUT_RUNTIME_UNKNOWN')

    def test_owner_died_filter_fallback_does_not_exist(self):
        for registered in (False,True):
            self.assertEqual(classify('v4',True,True,True,False,registered,'auth',False),
                             'NO_R19_MATCH_OR_BFE_UNAVAILABLE')

    def test_bfe_loss_not_claimed_safe(self):
        self.assertEqual(classify('v6',True,True,False,True,False,'redirect',False),
                         'NO_R19_MATCH_OR_BFE_UNAVAILABLE')

    def test_flags_mutation_flips_fallback(self):
        self.assertEqual(classify('v4',True,True,True,True,False,'auth',True),
                         'FILTER_TREATED_AS_PERMIT')

    def test_udp_sibling_not_covered(self):
        for selected,tcp in ((False,True),(True,False),(False,False)):
            self.assertEqual(classify('v6',selected,tcp,True,True,False,'auth',False),
                             'NO_R19_MATCH_OR_BFE_UNAVAILABLE')

    def test_no_packet_outcomes(self):
        for row in matrix():
            self.assertNotIn(row['result'], {'PACKET_ALLOW','PACKET_DROP','DIRECT','LEAK_FREE'})

    def test_canonical_rows(self):
        self.assertEqual(canonical().count('\n'), 256)


if __name__ == '__main__':
    unittest.main()
