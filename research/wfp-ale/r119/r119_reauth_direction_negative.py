#!/usr/bin/env python3
"""Deterministic negative witness, NOT a WFP/OS/packet test.

Windows ALE reauthorization returns to the flow's ORIGINAL authorization
layer, not a layer selected by the direction of the packet causing reauth.
Synthetic pairs deliberately share every user-mode observation while their
initial layer differs. Neither labels nor tuple/timing prove kernel origin.
"""
from __future__ import annotations
import hashlib
import itertools
import json

ORIGINS = ('OUT_CONNECT', 'IN_RECV_ACCEPT')
DIRECTIONS = ('OUT', 'IN')
REASONS = ('POLICY', 'INTERFACE', 'PENDING')
FAMILIES = (4, 6)
EPOCHS = ('SAME', 'REUSED_PID')
TICKETS = ('SAME', 'REUSED_TUPLE_NEW_TICKET')
WFP = ('PRESENT', 'LOST')
SSH = ('UP', 'DOWN')
TRANSPORTS = ('TCP', 'UDP')


def original_layer(origin: str, family: int) -> str:
    return ('AUTH_CONNECT' if origin == 'OUT_CONNECT' else 'AUTH_RECV_ACCEPT') + f'_V{family}'


def erroneous_layer(packet_direction: str, family: int) -> str:
    # The unsafe shortcut under test: incorrect as soon as direction reverses.
    return ('AUTH_CONNECT' if packet_direction == 'OUT' else 'AUTH_RECV_ACCEPT') + f'_V{family}'


def matrix() -> tuple[list[str], dict]:
    ordered = []
    mistakes = 0
    origin_ambiguity = 0
    observations: dict[tuple, set[str]] = {}
    witnesses = [
        ('OUT_CONNECT', 'IN', 'POLICY', 4, 'AUTH_CONNECT_V4', 'AUTH_RECV_ACCEPT_V4'),
        ('IN_RECV_ACCEPT', 'OUT', 'INTERFACE', 6, 'AUTH_RECV_ACCEPT_V6', 'AUTH_CONNECT_V6')
    ]
    for origin, direction, reason, family, epoch, ticket, wfp, ssh, transport in itertools.product(
        ORIGINS, DIRECTIONS, REASONS, FAMILIES, EPOCHS, TICKETS, WFP, SSH, TRANSPORTS
    ):
        actual = original_layer(origin, family)
        naive = erroneous_layer(direction, family)
        mismatched = actual != naive
        mistakes += mismatched
        # Tuple and process observations are purposely identical across both origins.
        # Reauth layer is NOT recoverable from that observation set.
        seen_key = (direction, reason, family, epoch, ticket, wfp, ssh, transport)
        observations.setdefault(seen_key, set()).add(actual)
        # An observation may corroborate consistency only, never grant kernel proof.
        weak_candidate = (origin == 'OUT_CONNECT' and epoch == 'SAME'
                          and ticket == 'SAME' and wfp == 'PRESENT'
                          and ssh == 'UP' and transport == 'TCP')
        status = 'CORROBORATION_NOT_PROOF' if weak_candidate else 'UNKNOWN_OR_OUT_OF_SCOPE'
        ordered.append(','.join(map(str, (
            origin, direction, reason, family, epoch, ticket, wfp, ssh, transport,
            actual, naive, int(mismatched), status))) + '\n')
    for layers in observations.values():
        assert len(layers) == 2, 'observation unexpectedly disambiguates original ALE layer'
        origin_ambiguity += 1
    assert len(ordered) == 768, len(ordered)
    assert mistakes == 384, mistakes
    assert origin_ambiguity == 384, origin_ambiguity
    # Two concrete, deterministic domain witnesses.
    assert original_layer('OUT_CONNECT', 4) == 'AUTH_CONNECT_V4'
    assert erroneous_layer('IN', 4) == 'AUTH_RECV_ACCEPT_V4'
    assert original_layer('IN_RECV_ACCEPT', 6) == 'AUTH_RECV_ACCEPT_V6'
    assert erroneous_layer('OUT', 6) == 'AUTH_CONNECT_V6'
    digest = hashlib.sha256(''.join(ordered).encode('utf-8')).hexdigest()
    return ordered, dict(
        scenarios=len(ordered), direction_only_misclassifications=mistakes,
        same_observation_opposite_origin_pairs=origin_ambiguity,
        sha256=digest, counterexamples=witnesses,
        kernel_origin_proof=False, system_no_direct_proof=False,
        real_wfp_calls=0, installed_driver=False)


if __name__ == '__main__':
    print(json.dumps(matrix()[1], sort_keys=True))
