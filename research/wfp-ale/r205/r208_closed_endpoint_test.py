"""R208: deterministic conditional stale CLAIM; PASS is a negative result, NOT WFP proof."""
import unittest

class Ticket:
    def __init__(self, close_observer=False):
        self.close_observer=close_observer
        self.s={}
        self.alive=True
    def issue(self,ep,family=4):
        if ep in self.s or not self.alive or family not in (4,6): return False
        self.s[ep]=[family,False,True]
        return True
    def auth(self,ep,family=4):
        s=self.s.get(ep)
        if not s or s[0]!=family or s[1] or not s[2]: return False
        s[1]=True
        return True
    def close(self,ep,match=True):
        # R19 does not register ALE_ENDPOINT_CLOSURE; observer is a proposed guard.
        if self.close_observer and match and ep in self.s:self.s[ep][2]=False
    def claim(self,ep):
        s=self.s.get(ep)
        if not s or not self.alive or not s[2]:return False
        s[2]=False
        return s[1]

class Negatives(unittest.TestCase):
    def test_closed_after_auth_v4_and_v6(self):
        for family in (4,6):
            a=Ticket();g=Ticket(True)
            for m in (a,g):
                self.assertTrue(m.issue(17,family));self.assertTrue(m.auth(17,family));m.close(17)
            self.assertTrue(a.claim(17));self.assertFalse(g.claim(17))
    def test_close_before_auth(self):
        a=Ticket();g=Ticket(True)
        for m in (a,g):self.assertTrue(m.issue(18));m.close(18)
        self.assertTrue(a.auth(18));self.assertFalse(g.auth(18))
        self.assertTrue(a.claim(18));self.assertFalse(g.claim(18))
    def test_sibling_close_is_not_selected_close(self):
        g=Ticket(True);self.assertTrue(g.issue(19));self.assertTrue(g.auth(19))
        g.close(19,match=False);self.assertTrue(g.claim(19))
    def test_reused_tuple_does_not_alias_endpoint(self):
        g=Ticket(True)
        for ep in (20,21):self.assertTrue(g.issue(ep));self.assertTrue(g.auth(ep))
        g.close(20);self.assertFalse(g.claim(20));self.assertTrue(g.claim(21))
    def test_no_auth_and_one_shot(self):
        a=Ticket();self.assertTrue(a.issue(22));self.assertFalse(a.claim(22))
        self.assertTrue(a.issue(23));self.assertTrue(a.auth(23));self.assertTrue(a.claim(23));self.assertFalse(a.claim(23))
    def test_process_death_denies(self):
        a=Ticket();a.issue(24);a.auth(24);a.alive=False;self.assertFalse(a.claim(24))

if __name__=='__main__':unittest.main(verbosity=2)
