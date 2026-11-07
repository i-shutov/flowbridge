#!/usr/bin/env python3
"""Independent adversarial lifecycle audit for the offline R4/R5 model.

No drivers, filters, network, or OS APIs; synthetic inputs cannot authenticate
WFP kernel events. The expected verdict is derived from a *separate* matrix,
not from the tested gate's return value.
"""
from __future__ import annotations

from itertools import product
from pathlib import Path
import ast
import hashlib
import json

from endpoint_witness_model import ResearchGate, Owner, Redirect, Authorization

APP = b'ntpath:A'
IMAGE = b'file-object:A'
TUPLE4 = '192.0.2.10:443'
TUPLE6 = '[2001:db8::10]:443'


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def baseline():
    g = ResearchGate(APP, 77)
    require(g.start_process(Owner(501, 1, 901, APP, IMAGE, True)) == 'REGISTERED_MODEL', 'register original')
    require(g.classify(Redirect(9, 77, 700, 501, 1, APP, 4, TUPLE4)) == 'CAPTURED_MODEL', 'classify original')
    require(g.observe_auth(Authorization(700, 501, 1, IMAGE, 4)) == 'SUPPORTING_OBSERVATION_ONLY', 'original auth')
    return g


def main():
    source = (Path(__file__).parent / 'endpoint_witness_model.py').read_text(encoding='utf-8')
    ast.parse(source)
    require('import socket' not in source and 'ctypes' not in source and 'subprocess' not in source,
            'research model unexpectedly gained OS/network bridge')
    outcomes = {'negative': 0, 'conditional_only': 0}
    case = 0
    # Seven independent dimensions, including PID generation replay, epoch reuse,
    # endpoint-handle lifetime, ticket replay, absent AUTH_CONNECT, spoofed socket
    # provenance and SSH loss; both IPv4 and IPv6 are covered.
    for generation, epoch, endpoint, ticket, fresh_auth, genuine_receipt, ssh_ready, family in product(
        (1, 2), (901, 902), (700, 701), (9, 10), (False, True),
        (False, True), (False, True), (4, 6)
    ):
        case += 1
        g = baseline()
        require(g.stop_process(501, 1) == 'REVOKED_MODEL', f'case {case}: process termination')
        # stop_process MUST also retire supporting old AUTH and old endpoint.
        require(700 in g.poisoned_endpoints and 700 not in g.auth,
                f'case {case}: old endpoint remains reusable after exit')
        new_owner = Owner(501, generation, epoch, APP, IMAGE, True)
        registered = g.start_process(new_owner)
        expected_register = ('REUSED_GENERATION' if generation == 1
                             else 'REUSED_EPOCH' if epoch == 901
                             else 'REGISTERED_MODEL')
        require(registered == expected_register,
                f'case {case}: unexpected generation/epoch admission: {registered}')
        g.ssh_ready = ssh_ready
        request = Redirect(ticket, 77, endpoint, 501, generation, APP,
                           family, TUPLE4 if family == 4 else TUPLE6)
        classified = g.classify(request)
        if fresh_auth:
            g.observe_auth(Authorization(endpoint, 501, generation, IMAGE, family))
        actual = (g.accept(ticket, 77, endpoint, family, genuine_receipt, True, True)
                  if classified == 'CAPTURED_MODEL' else 'REJECT_INGRESS')
        # No path/tuple/handle-only correlation is admissible after exit.
        # The only positive case needs a fresh *synthetic* registration and
        # observation, a new endpoint, new ticket and authenticated receipt.
        allow_model = (generation == 2 and epoch == 902 and endpoint == 701
                       and ticket == 10 and fresh_auth and genuine_receipt and ssh_ready)
        expected = 'CONDITIONAL_MODEL_ONLY' if allow_model else 'REJECT_INGRESS'
        require(actual == expected,
                f'case {case}: expected {expected}, got {actual} '
                f'{(generation, epoch, endpoint, ticket, fresh_auth, genuine_receipt, ssh_ready, family)}')
        outcomes['conditional_only' if allow_model else 'negative'] += 1

    # Conflict persists after apparent legitimate resynchronization, including
    # an explicit observation that reappears byte-for-byte identical.
    g = baseline()
    require(g.observe_auth(Authorization(700, 501, 2, IMAGE, 4)) == 'AMBIGUOUS_ENDPOINT', 'conflict not noticed')
    require(g.observe_auth(Authorization(700, 501, 1, IMAGE, 4)) == 'AMBIGUOUS_ENDPOINT', 'conflict healed incorrectly')
    require(g.accept(9, 77, 700, 4, True, True, True) == 'REJECT_INGRESS', 'conflict admitted')
    # Unmatched stale exit must revoke *all* pending and supporting state.
    g = baseline()
    require(g.stop_process(501, 2) == 'STALE_EXIT', 'stale exit not rejected')
    require(700 not in g.auth and 700 in g.poisoned_endpoints, 'stale exit retained auth evidence')
    require(g.accept(9, 77, 700, 4, True, True, True) == 'REJECT_INGRESS', 'stale exit admitted')
    # Different PID reuses an endpoint number; do not trust a recycled handle.
    g = baseline()
    require(g.stop_process(501, 1) == 'REVOKED_MODEL', 'stop baseline')
    require(g.start_process(Owner(502, 1, 903, APP, IMAGE, True)) == 'REGISTERED_MODEL', 'start sibling')
    require(g.classify(Redirect(10, 77, 700, 502, 1, APP, 4, TUPLE4)) == 'AMBIGUOUS_ENDPOINT',
            'same transport endpoint reused by other pid')

    # Exit before any AUTH_CONNECT observation must poison an in-flight
    # endpoint too. Otherwise a later unrelated classify could reuse its ID.
    g = ResearchGate(APP, 77)
    require(g.start_process(Owner(501, 1, 901, APP, IMAGE, True)) == 'REGISTERED_MODEL', 'pending-only owner')
    require(g.classify(Redirect(9, 77, 700, 501, 1, APP, 4, TUPLE4)) == 'CAPTURED_MODEL', 'pending-only classify')
    require(g.stop_process(501, 1) == 'REVOKED_MODEL', 'pending-only stop')
    require(700 in g.poisoned_endpoints, 'pending endpoint not poisoned at process death')
    require(g.start_process(Owner(502, 1, 903, APP, IMAGE, True)) == 'REGISTERED_MODEL', 'pending-only second owner')
    require(g.classify(Redirect(10, 77, 700, 502, 1, APP, 4, TUPLE4)) == 'AMBIGUOUS_ENDPOINT',
            'pending-only endpoint incorrectly reused')

    # An observation with no retained classify also has a finite lifetime.
    g = ResearchGate(APP, 77)
    require(g.start_process(Owner(501, 1, 901, APP, IMAGE, True)) == 'REGISTERED_MODEL', 'auth-only owner')
    require(g.observe_auth(Authorization(700, 501, 1, IMAGE, 4)) == 'UNBOUND_AUTH',
            'AUTH without pending classify must not create evidence')
    require(700 not in g.auth and 700 not in g.auth_ticket, 'orphan AUTH observation persisted')
    require(g.stop_process(501, 1) == 'REVOKED_MODEL', 'auth-only exit')
    require(700 not in g.auth and 700 not in g.auth_ticket, 'orphan AUTH survived exit')

    print(json.dumps({
        'ok': True,
        'exhaustive_synthetic_traces': case,
        'outcomes': outcomes,
        'extra_assertion_groups': 5,
        'r4_r5_source_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest(),
        'kernel_origin_proved': False,
        'system_no_direct_proved': False,
        'packet_bound_proved': False,
        'windows_native_executed': False,
    }, sort_keys=True))


if __name__ == '__main__':
    main()
