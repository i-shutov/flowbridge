"""R209 source-consistent, conditional WFP AUTH self-block counterexample.
No Windows calls, network, driver, filters, sockets or installations. PASS != kernel proof.
"""
from dataclasses import dataclass
import unittest

SELECTED = 'selected-original.exe'
BROKER = 'flowbridge-broker.exe'
PROXY_PORT = {4: 19094, 6: 19096}

@dataclass(frozen=True)
class Indication:
    family: int
    original_app: str
    current_app: str
    process: str
    remote_ip: str
    remote_port: int
    redirected: bool
    tcp: bool = True
    kernel_ticket: bool = False
    records_set: bool = False


def dispatch(i: Indication) -> str:
    # R19 policy_windows.rs: AUTH_CONNECT V4/V6, ORIGINAL_APP_ID == selected, TCP.
    if not i.tcp or i.original_app != SELECTED:
        return 'FILTER_NOT_MATCHED'
    # R19 redirect.rs: auth_check requires redirected + selected original
    # process + exact local IPv4/IPv6 loopback and configured broker port.
    loopback = {4: '127.0.0.1', 6: '::1'}[i.family]
    valid = (i.redirected and i.process == SELECTED and
             i.remote_ip == loopback and i.remote_port == PROXY_PORT[i.family] and
             i.kernel_ticket)
    return 'PERMIT_AND_ATTEST' if valid else 'BLOCK'


def original(family: int) -> Indication:
    return Indication(family, SELECTED, SELECTED, SELECTED,
                      {4:'127.0.0.1', 6:'::1'}[family], PROXY_PORT[family], True,
                      kernel_ticket=True)


def tagged_ssh(family: int, server='198.51.100.44') -> Indication:
    # Hypothesis from official WFP tracking contract: SET_RECORDS propagates
    # ORIGINAL_APP_ID on the new proxy socket before connect().
    return Indication(family, SELECTED, BROKER, BROKER, server, 22, True,
                      records_set=True)

class Negative(unittest.TestCase):
    def test_original_v4(self): self.assertEqual(dispatch(original(4)), 'PERMIT_AND_ATTEST')
    def test_original_v6(self): self.assertEqual(dispatch(original(6)), 'PERMIT_AND_ATTEST')
    def test_tagged_ssh_v4_self_block(self): self.assertEqual(dispatch(tagged_ssh(4)), 'BLOCK')
    def test_tagged_ssh_v6_self_block(self): self.assertEqual(dispatch(tagged_ssh(6)), 'BLOCK')
    def test_ssh_even_if_server_loopback(self):
        for f, addr in [(4, '127.0.0.1'), (6, '::1')]:
            self.assertEqual(dispatch(tagged_ssh(f, addr)), 'BLOCK')
    def test_selected_sibling_direct_block(self):
        self.assertEqual(dispatch(Indication(4,SELECTED,SELECTED,SELECTED,'203.0.113.2',443,False)), 'BLOCK')
    def test_foreign_broker_untagged_not_matched(self):
        # Not a success: missing records removes ORIGINAL_APP_ID coverage.
        self.assertEqual(dispatch(Indication(4,BROKER,BROKER,BROKER,'198.51.100.44',22,False)), 'FILTER_NOT_MATCHED')
    def test_udp_dns_not_covered_by_tcp_rule(self):
        self.assertEqual(dispatch(Indication(4,SELECTED,SELECTED,SELECTED,'8.8.8.8',53,False,tcp=False)), 'FILTER_NOT_MATCHED')
    def test_records_flag_is_not_an_authorization_credential(self):
        p=tagged_ssh(4)
        self.assertTrue(p.records_set)
        self.assertEqual(dispatch(p),'BLOCK')

if __name__=='__main__': unittest.main(verbosity=2)
