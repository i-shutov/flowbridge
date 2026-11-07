"""Actual-source R22 unit tests; no Windows calls; never a kernel proof."""
import itertools
import unittest
import r22_visibility_ambiguity as m

class R22Tests(unittest.TestCase):
    def test_ambiguous_filter_session_owner(self):
        for w1,w2 in m.enumerate_indistinguishable_pairs():
            self.assertEqual(w1.inventory,w2.inventory)
            self.assertFalse(w1.survives_exit('A'))
            self.assertTrue(w2.survives_exit('A'))
    def test_provenance_not_present_in_view(self):
        w1,w2=m.indistinguishable_worlds(4,'TCP')
        self.assertNotIn('filter_creator_session',w1.inventory.__dataclass_fields__)
        self.assertNotIn('source_process_epoch',w1.inventory.__dataclass_fields__)
        self.assertNotEqual(w1.source_process_epoch,w2.source_process_epoch)
    def test_provider_key_is_not_creator_session(self):
        w1,w2=m.indistinguishable_worlds(6,'TCP')
        self.assertEqual(w1.inventory.filters[0].provider_key,w2.inventory.filters[0].provider_key)
        self.assertNotEqual(w1.filter_creator_session,w2.filter_creator_session)
    def test_manager_pid_is_not_network_origin(self):
        w1,w2=m.indistinguishable_worlds(4,'UDP')
        self.assertEqual(w1.inventory.sessions[0].manager_pid,510)
        self.assertNotEqual(w1.source_process_epoch,w2.source_process_epoch)
    def test_unregistered_permit_flag_is_single_filter_only(self):
        for family in m.FAMILIES:
            f=m.indistinguishable_worlds(family,'TCP',{'PERMIT_IF_CALLOUT_UNREGISTERED'})[0].inventory.filters[0]
            self.assertEqual(m.local_filter_signal(f,False),
                             'THIS_FILTER_TREATED_AS_PERMIT_IF_CALLOUT_MISSING')
            self.assertFalse(m.certify_no_direct(m.indistinguishable_worlds(family,'TCP')[0].inventory,
                                                   policy_committed=True,selected_appid_known=True,
                                                   kernel_receipt=True))
    def test_permit_flag_requires_missing_callout(self):
        f=m.indistinguishable_worlds(6,'TCP',{'PERMIT_IF_CALLOUT_UNREGISTERED'})[0].inventory.filters[0]
        self.assertEqual(m.local_filter_signal(f,True),'NO_SAFETY_INFERENCE_FROM_THIS_FILTER')
        self.assertEqual(m.local_filter_signal(f,None),'UNKNOWN_CALLOUT_STATE')
    def test_permit_flag_not_interpreted_for_noncallout(self):
        f=m.Filter('F',1,'P',4,'TCP',frozenset({'PERMIT_IF_CALLOUT_UNREGISTERED'}),'BLOCK','')
        self.assertEqual(m.local_filter_signal(f,False),'NO_SAFETY_INFERENCE_FROM_THIS_FILTER')
    def test_disabled_filter_not_active_block_proof(self):
        f=m.Filter('F',1,'P',4,'TCP',frozenset({'DISABLED','PERMIT_IF_CALLOUT_UNREGISTERED'}),'CALLOUT_TERMINATING','C')
        self.assertEqual(m.local_filter_signal(f,False),'DISABLED_FILTER_NOT_AN_ACTIVE_BLOCK_PROOF')
    def test_persistent_and_boottime_cannot_certify(self):
        for flag in ('PERSISTENT','BOOTTIME'):
            for family in m.FAMILIES:
                f=m.Filter('F',1,'P',family,'TCP',frozenset({flag}),'BLOCK','')
                view=m.Inventory((),(f,),100,101)
                self.assertFalse(m.certify_no_direct(view,policy_committed=True,
                                  selected_appid_known=True,kernel_receipt=True))
    def test_separate_snapshot_epochs_not_atomic(self):
        w,_=m.indistinguishable_worlds(4,'TCP')
        self.assertNotEqual(w.inventory.session_snapshot_epoch,w.inventory.filter_snapshot_epoch)
    def test_partial_acl_inventory_cannot_certify(self):
        w,_=m.indistinguishable_worlds(6,'TCP')
        self.assertFalse(w.inventory.visibility_complete)
        self.assertFalse(m.certify_no_direct(w.inventory,policy_committed=True,
                                                 selected_appid_known=True,kernel_receipt=True))
    def test_all_combinations_no_certification(self):
        n=0
        for a,b in m.enumerate_indistinguishable_pairs():
            for world in (a,b):
                for commit,appid,receipt in itertools.product((False,True),repeat=3):
                    self.assertFalse(m.certify_no_direct(world.inventory,
                         policy_committed=commit,selected_appid_known=appid,kernel_receipt=receipt))
                    n+=1
        self.assertEqual(n,256)
    def test_invalid_family_and_transport(self):
        for family,transport in ((0,'TCP'),(4,'ICMP'),(7,'UDP')):
            with self.assertRaises(ValueError):m.indistinguishable_worlds(family,transport)
    def test_aggregate_count_and_gates(self):
        c=m.counts()
        self.assertEqual(c['indistinguishable_pairs'],16)
        self.assertEqual(c['different_hidden_survival'],16)
        self.assertFalse(c['system_no_direct_proved'])
        self.assertFalse(c['g2_pass'])

if __name__=='__main__':unittest.main(verbosity=2)
