"""Independent offline negative verification of the real R21 module.

No synthetic comparison is labelled a native Windows result.
"""
from dataclasses import replace
from itertools import product
import unittest
import policy_barrier_r21 as p

class PolicyBarrier(unittest.TestCase):
    def test_indistinguishable_views_all_144_cases(self):
        pairs = list(p.all_pairs())
        self.assertEqual(len(pairs), 2*2*3*2*2*3)
        for one, two in pairs:
            self.assertEqual(one.view, two.view)
            self.assertTrue(one.all_existing_flows_revalidated)
            self.assertFalse(two.all_existing_flows_revalidated)
            self.assertFalse(p.can_infer_post_commit_barrier(one.view))
            self.assertFalse(p.global_no_direct_proved(one, two))

    def test_snapshot_truthiness_is_not_implicit_barrier(self):
        for one, two in p.all_pairs():
            self.assertTrue(all([one.view.commit_ok, one.view.filter_enumerated,
                                 one.view.current_wfp_poll_ok, one.view.current_ssh_poll_ok]))
            self.assertFalse(p.can_infer_post_commit_barrier(two.view))

    def test_reused_tuple_cannot_synthesize_provenance(self):
        a = p.Flow(101, 19, 5, 100, b'full-AppId-A', 4, 'TCP','192.0.2.2:443')
        b = replace(a, source_event_token=102, creation_epoch=101)
        evidence = self.auth(a)
        self.assertTrue(p.event_bound_observation(a, evidence, 7))
        self.assertFalse(p.event_bound_observation(b, evidence, 7))

    @staticmethod
    def auth(f):
        return p.Auth(f.source_event_token, f.session, f.pid, f.creation_epoch,
                      f.appid, f.family, f.transport, f.tuple, 7, True,
                      'BLOCK', True, True)

    def test_each_missing_provenance_field_rejected(self):
        for family, transport in product((4,6), ('TCP','UDP')):
            f=p.Flow(101,19,5,100,b'opaque-AppId',family,transport,'endpoint')
            e=self.auth(f)
            self.assertTrue(p.event_bound_observation(f,e,7))
            for name,value in [
                ('source_event_token',102),('session',20),('pid',6),
                ('creation_epoch',101),('appid',b'other-AppId'),('appid',None),
                ('family',6 if family==4 else 4),
                ('transport','UDP' if transport=='TCP' else 'TCP'),
                ('tuple','other'),('policy_epoch',6),('is_reauthorize',False),
                ('action','PERMIT'),('from_kernel_event',False),('fields_known',False)]:
                with self.subTest(family=family,transport=transport,name=name,value=value):
                    self.assertFalse(p.event_bound_observation(f,replace(e,**{name:value}),7))
            self.assertFalse(p.event_bound_observation(f,e,8))
            self.assertFalse(p.event_bound_observation(f,e,0))

    def test_reauthorization_from_reverse_direction_not_an_original_owner_proof(self):
        # Direction is intentionally not used as original owner authority.
        # If original process/identity is unavailable (FWP_EMPTY), reject.
        f=p.Flow(1,19,8,90,b'opaque-AppId',6,'UDP','endpoint')
        e=replace(self.auth(f),appid=None,fields_known=False)
        self.assertFalse(p.event_bound_observation(f,e,7))

    def test_non_native_correlation_cannot_supply_kernel_event(self):
        f=p.Flow(1,19,8,90,b'opaque-AppId',4,'TCP','endpoint')
        e=self.auth(f)
        for origin in (False,):
            self.assertFalse(p.event_bound_observation(f,replace(e,from_kernel_event=origin),7))

    def test_out_of_scope_and_wfp_ssh_losses_not_global_proof(self):
        for one, two in p.all_pairs():
            self.assertFalse(p.global_no_direct_proved(one, two))

    def test_dynamic_wfp_session_teardown_is_policy_loss_not_route_safety(self):
        self.assertEqual(p.policy_object_after_owner_exit('dynamic', True),
                         'POLICY_OBJECT_REMOVED')
        self.assertEqual(p.policy_object_after_owner_exit('dynamic', False),
                         'ENFORCEMENT_UNPROVEN')
        for lifetime in ('static','persistent'):
            self.assertEqual(p.policy_object_after_owner_exit(lifetime, True),
                             'ENFORCEMENT_UNPROVEN')
        with self.assertRaises(ValueError):
            p.policy_object_after_owner_exit('sessionless', True)

    def test_stale_zero_process_and_event_fields_rejected(self):
        f=p.Flow(1,19,8,90,b'opaque-AppId',4,'TCP','endpoint')
        e=self.auth(f)
        for n in ('source_event_token','pid','creation_epoch'):
            self.assertFalse(p.event_bound_observation(replace(f,**{n:0}),e,7))
        self.assertFalse(p.event_bound_observation(replace(f,appid=b''),e,7))

if __name__=='__main__': unittest.main(verbosity=2)
