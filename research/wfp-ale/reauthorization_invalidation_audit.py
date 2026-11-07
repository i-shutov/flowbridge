#!/usr/bin/env python3
"""R13 independent negative oracle: no pending AUTH survives reauthorization/unknown data.

Pure stdlib. Synthetic test-only evidence. No WFP, sockets, services, drivers,
filters, subprocesses, filesystem modifications, or system state. A conditional
model success is never real kernel ownership or no-DIRECT proof.
"""
from __future__ import annotations

import ast
import hashlib
import itertools
import json
from pathlib import Path
from endpoint_witness_model import Authorization, Owner, Redirect, ResearchGate

APP = b'opaque-full-wfp-appid'
IMAGE = b'opaque-image-object'
SESSION = 8081
PID = 501
ENDPOINT = 731
TICKET = 902


def setup(family: int, endpoint: int = ENDPOINT):
    gate = ResearchGate(APP, SESSION)
    assert gate.start_process(Owner(PID, 4, 133_000_000_123, APP, IMAGE, True)) == 'REGISTERED_MODEL'
    request = Redirect(TICKET, SESSION, endpoint, PID, 4, APP, family,
                       '192.0.2.42:443' if family == 4 else '[2001:db8::42]:443')
    assert gate.classify(request) == 'CAPTURED_MODEL'
    return gate, request


def event(family: int, endpoint: int = ENDPOINT, *, reauthorize=False,
          image=IMAGE) -> Authorization:
    return Authorization(endpoint, PID, 4, image, family, reauthorize)


def accept(gate, request):
    return gate.accept(request.ticket, request.session, request.endpoint,
                       request.family, True, True, True)


def assert_retired(gate, request):
    assert request.ticket in gate.retired, 'auth revocation must retire the pending ticket'
    assert request.endpoint in gate.poisoned_endpoints, 'reused endpoint must remain quarantined'
    assert request.endpoint not in gate.auth, 'no reusable AUTH may survive'
    assert request.endpoint not in gate.auth_ticket, 'no bound AUTH ticket may survive'
    assert request.ticket not in gate.redirects, 'no pending classify may survive'
    assert accept(gate, request) == 'REJECT_INGRESS', 'revoked evidence must not route'
    new = Redirect(request.ticket + 1, request.session, request.endpoint, request.pid,
                   request.generation, request.app_id, request.family, request.destination)
    assert gate.classify(new) == 'AMBIGUOUS_ENDPOINT', 'endpoint resurrection'


def verify_source_surface():
    path = Path(__file__).with_name('endpoint_witness_model.py')
    raw = path.read_bytes()
    parsed = ast.parse(raw)
    names = {n.name for n in ast.walk(parsed) if isinstance(n, (ast.ClassDef, ast.FunctionDef))}
    assert {'ResearchGate', 'Authorization', 'observe_auth', '_retire_endpoint', 'accept'} <= names
    # Static safety is supplementary to review, never native proof.
    assert b'import ctypes' not in raw and b'import subprocess' not in raw
    return hashlib.sha256(raw).hexdigest()


def run() -> dict:
    source_digest = verify_source_surface()
    n = 0
    # Event ordering: reauthorization may come before or after a matching
    # initial AUTH observation. Reauth never grants/extends initial authority.
    for fam, had_initial, flavor in itertools.product((4, 6), (False, True),
                                                       ('reauthorize', 'reauth_empty_path',
                                                        'reauth_unknown_family', 'unknown_flag',
                                                        'malformed_initial_path',
                                                        'malformed_initial_family')):
        g, r = setup(fam)
        if had_initial:
            assert g.observe_auth(event(fam)) == 'SUPPORTING_OBSERVATION_ONLY'
        invalid = {
            'reauthorize': event(fam, reauthorize=True),
            'reauth_empty_path': event(fam, reauthorize=True, image=b''),
            'reauth_unknown_family': event(0, reauthorize=True),
            'unknown_flag': event(fam, reauthorize=None),
            'malformed_initial_path': event(fam, image=b''),
            'malformed_initial_family': event(0),
        }[flavor]
        result = g.observe_auth(invalid)
        expected = 'REAUTHORIZE_NOT_NEW_PROOF' if flavor.startswith('reauth') else 'INVALID_AUTH'
        if flavor == 'unknown_flag':
            expected = 'INVALID_AUTH'
        assert result == expected, (fam, had_initial, flavor, result, expected)
        assert_retired(g, r)
        n += 1

    # Mutation controls: unrelated numeric endpoint must not poison a valid
    # contemporaneous ticket. The only accepted result is a MODEL candidate.
    for fam, initial, wrong_end in itertools.product((4, 6), (False, True), (0, 1)):
        g, r = setup(fam)
        assert g.observe_auth(event(fam)) == 'SUPPORTING_OBSERVATION_ONLY'
        bad_endpoint = ENDPOINT + 100 + wrong_end
        assert g.observe_auth(event(fam, bad_endpoint, reauthorize=True)) == 'REAUTHORIZE_NOT_NEW_PROOF'
        assert g.observe_auth(event(fam, bad_endpoint, image=b'')) == 'INVALID_AUTH'
        assert accept(g, r) == 'CONDITIONAL_MODEL_ONLY'
        n += 1

    # Explicitly preserve process-generation, same-basename, SSH-loss and
    # IPv4/IPv6 boundaries while testing adversarial auth lifetimes.
    for fam in (4, 6):
        g, r = setup(fam)
        assert g.observe_auth(event(fam)) == 'SUPPORTING_OBSERVATION_ONLY'
        assert g.stop_process(PID, 4) == 'REVOKED_MODEL'
        assert accept(g, r) == 'REJECT_INGRESS'
        n += 1
        g, r = setup(fam)
        assert g.observe_auth(event(fam)) == 'SUPPORTING_OBSERVATION_ONLY'
        assert g.loss('ssh') == 'OWNED_INGRESS_CLOSED_ONLY'
        assert accept(g, r) == 'REJECT_INGRESS'
        n += 1
        g, r = setup(fam)
        sibling = Redirect(TICKET+1,SESSION,ENDPOINT+2,PID,4,b'other-same-basename-AppId',fam,r.destination)
        assert g.classify(sibling) == 'OUTSIDE_SCOPE'
        n += 1
    return {'r13_cases_passed': n, 'endpoint_source_sha256': source_digest,
            'synthetic_only': True, 'real_windows_calls': 0,
            'kernel_origin_proved': False, 'g2_accepted': False,
            'packetbound': False, 'system_no_direct': False,
            'release_accepted': False}


if __name__ == '__main__':
    print(json.dumps(run(), sort_keys=True))
