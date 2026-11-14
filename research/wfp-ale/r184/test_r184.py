"""R184 deterministic negative tests; independent of WFP device and network."""
import unittest
from r184_dynamic_session_negative import row, matrix, event_trace

class DynamicLifetime(unittest.TestCase):
    def test_matrix_is_exhaustive_for_defined_axes(self):
        self.assertEqual(len(matrix()),64)
        self.assertEqual(len({(r['family'],r['protocol'],r['origin'],r['external_blocker'],r['scenario']) for r in matrix()}),64)
    def test_exit_erases_own_dynamic_objects_even_if_driver_unmodified(self):
        self.assertEqual(event_trace('owner_exit')[0][-1],('owner_exit',0))
        for family in ('v4','v6'):
            self.assertTrue(row(family,'tcp','selected',False,'owner_exit')['owned_gap'])
    def test_close_before_replacement_has_gap(self):
        self.assertEqual(event_trace('close_then_replace')[0][1],('close_old',0))
        self.assertTrue(row('v4','tcp','selected',True,'close_then_replace')['owned_gap'])
    def test_same_fixed_sublayer_guid_prevents_modelled_overlap(self):
        trace, collision = event_trace('fixed_key_overlap')
        self.assertEqual(collision,1)
        self.assertEqual(trace,[('baseline',1),('stage_new_fixed',1),('close_old',0),('retry_new',1)])
    def test_distinct_guid_hypothesis_is_only_ownership_continuity(self):
        trace, collision=event_trace('distinct_key_overlap')
        self.assertEqual(collision,0)
        self.assertEqual([x[1] for x in trace],[1,2,1])
        self.assertEqual(row('v6','tcp','selected',False,'distinct_key_overlap')['effective_result'],'UNKNOWN')
    def test_sibling_direct_outside_selected_appid_filter(self):
        self.assertTrue(all(not r['owned_gap'] for r in matrix() if r['origin']=='sibling'))
        self.assertTrue(all('baseline:0' in r['timeline'] for r in matrix() if r['origin']=='sibling'))
    def test_udp_dns_quic_outside_tcp_only_filter(self):
        self.assertTrue(all('baseline:0' in r['timeline'] for r in matrix() if r['protocol']=='udp'))
    def test_external_filters_never_disguised_as_own_coverage(self):
        a=row('v4','tcp','selected',False,'owner_exit')
        b=row('v4','tcp','selected',True,'owner_exit')
        self.assertEqual(a['timeline'],b['timeline'])
        self.assertEqual(a['effective_result'],b['effective_result'])
        self.assertNotEqual(a['alternative_guard_may_block'],b['alternative_guard_may_block'])
    def test_contract_mutation_visible_in_unique_node_oracle(self):
        # Simulated unsafe mutation: treating a dynamic owner-death as
        # retaining its own objects violates both current model and source.
        false_post_exit_count=1
        self.assertNotEqual(false_post_exit_count,event_trace('owner_exit')[0][-1][1])

if __name__ == '__main__': unittest.main()
