"""R202 independent negative oracle for documented dynamic WFP policy lifetime.
No Windows APIs, packets, drivers, side effects or runtime WFP claims.
"""
import unittest

RULES = frozenset(('REDIRECT4', 'REDIRECT6', 'AUTH4', 'AUTH6'))

class World:
    def __init__(self):
        self.dynamic_session = True
        self.owned_rules = set(RULES)
        self.kernel_registered = True
        self.ssh_ok = True
    def session_owner_exit(self):
        # Microsoft FWPM_SESSION_FLAG_DYNAMIC documented postcondition.
        self.dynamic_session = False
        self.owned_rules.clear()
    def evidence(self, family=4, proto=6, foreign_policy=False):
        if foreign_policy: return 'UNKNOWN_FOREIGN'
        required = {f'REDIRECT{family}', f'AUTH{family}'}
        if not self.dynamic_session: return 'OWNED_FILTERS_ABSENT'
        if proto != 6 or not self.kernel_registered: return 'NOT_ESTABLISHED'
        return 'PRESENT_NOT_PROVEN' if required <= self.owned_rules else 'NOT_ESTABLISHED'

class Negative(unittest.TestCase):
    def test_symmetric_v4_v6_when_session_alive(self):
        w=World()
        for f in (4,6): self.assertEqual(w.evidence(f),'PRESENT_NOT_PROVEN')
    def test_session_owner_exit_removes_four_owned_objects(self):
        w=World();w.session_owner_exit()
        self.assertEqual(w.owned_rules,set())
        for f in (4,6):self.assertEqual(w.evidence(f),'OWNED_FILTERS_ABSENT')
    def test_kernel_callout_survival_does_not_supply_filter(self):
        w=World();w.session_owner_exit()
        self.assertTrue(w.kernel_registered)
        self.assertEqual(w.evidence(),'OWNED_FILTERS_ABSENT')
    def test_foreign_policy_cannot_support_leak_inference(self):
        w=World();w.session_owner_exit()
        self.assertEqual(w.evidence(foreign_policy=True),'UNKNOWN_FOREIGN')
    def test_udp_dns_quic_out_of_scope_even_when_policy_alive(self):
        w=World()
        for f in (4,6):self.assertEqual(w.evidence(f,17),'NOT_ESTABLISHED')
    def test_ssh_loss_is_not_equivalent_to_filter_removal(self):
        w=World();w.ssh_ok=False
        self.assertEqual(w.evidence(),'PRESENT_NOT_PROVEN')
        self.assertTrue(w.dynamic_session)
    def test_missing_registration_no_verified_enforcement(self):
        w=World();w.kernel_registered=False
        self.assertEqual(w.evidence(6),'NOT_ESTABLISHED')

if __name__ == '__main__':unittest.main(verbosity=2)
