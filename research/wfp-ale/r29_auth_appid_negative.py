#!/usr/bin/env python3
"""R29 offline cross-identity tests; no WFP, network, driver or kernel calls.

This is a projection of the exact R26 auth_check conjunction, not a Windows
execution. `redirected` controls all the OTHER WFP witness requirements.
"""
import unittest
from dataclasses import dataclass

SOURCE_COMMIT = 'e4074ac63bc710c27958e515fbf199b87ced5640'
SOURCE_BLOB = '6330935a8366d8ac573cbb2b474626f5883881f9'

@dataclass(frozen=True)
class Observation:
    family: int
    original_app: str
    current_app: str
    selected_app: str = 'selected.exe'
    redirected: bool = True
    origin_epoch_ok: bool = True
    endpoint_ok: bool = True
    original_destination_ok: bool = True
    broker_pid_ok: bool = True
    context_valid: bool = True
    healthy: bool = True
    protocol: str = 'tcp'


def source_auth_projection(x: Observation) -> bool:
    # From redirect.rs: orig and current_app MUST both equal route.name.
    # All remaining R26 checks are held constant by other_witness().
    return (x.original_app == x.selected_app
            and x.current_app == x.selected_app
            and other_witness(x))


def other_witness(x: Observation) -> bool:
    return (x.family in (4, 6) and x.protocol == 'tcp'
            and x.redirected and x.origin_epoch_ok and x.endpoint_ok
            and x.original_destination_ok and x.broker_pid_ok
            and x.context_valid and x.healthy)


class ContractTests(unittest.TestCase):
    def test_legitimate_proxy_current_app_can_fail_source_gate(self):
        # WFP documents ORIGINAL_APP_ID separately from APP_ID on proxies.
        # The OS must still be measured to establish this exact inbound state.
        for family in (4, 6):
            with self.subTest(family=family):
                selected = Observation(family, 'selected.exe', 'selected.exe')
                proxied = Observation(family, 'selected.exe', 'broker.exe')
                self.assertTrue(source_auth_projection(selected))
                self.assertFalse(source_auth_projection(proxied))
                self.assertTrue(other_witness(proxied))

    def test_original_app_must_still_be_selected(self):
        for family in (4, 6):
            for original in ('broker.exe', 'sibling.exe', ''):
                x = Observation(family, original, 'selected.exe')
                with self.subTest(family=family, original=original):
                    self.assertFalse(source_auth_projection(x))

    def test_missing_or_wrong_metadata_stays_negative(self):
        for family in (4, 6):
            for key in ('redirected', 'origin_epoch_ok', 'endpoint_ok',
                        'original_destination_ok', 'broker_pid_ok',
                        'context_valid', 'healthy'):
                kwargs = dict(family=family, original_app='selected.exe',
                              current_app='selected.exe')
                kwargs[key] = False
                with self.subTest(family=family, missing=key):
                    self.assertFalse(source_auth_projection(Observation(**kwargs)))

    def test_udp_not_transparently_covered(self):
        for family in (4, 6):
            self.assertFalse(source_auth_projection(Observation(
                family, 'selected.exe', 'selected.exe', protocol='udp')))

    def test_fail_open_mutant_detected(self):
        # Mutant that would accept arbitrary original app is unacceptable.
        def mutant_current_only(x):
            return x.current_app == x.selected_app and other_witness(x)
        for family in (4, 6):
            x = Observation(family, 'sibling.exe', 'selected.exe')
            self.assertTrue(mutant_current_only(x))
            self.assertFalse(source_auth_projection(x))

if __name__ == '__main__':
    unittest.main(verbosity=2)
