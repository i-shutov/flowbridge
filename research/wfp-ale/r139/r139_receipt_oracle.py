#!/usr/bin/env python3
"""R139 test-only logical gate: no driver, WFP, sockets, or kernel evidence."""
import hashlib
import itertools
import json

GATES = (
    'accepted_socket_wfp_query', 'records_returned', 'context_returned',
    'context_parsed', 'kernel_claim_success', 'outbound_socket_created',
    'redirect_records_set', 'outbound_connected', 'ssh_host_key_pinned',
    'ssh_channel_open', 'not_revoked',
)
STAGES = (
    'NO_TRUSTED_ACCEPT', 'RECORD_QUERY_FAILED', 'CONTEXT_QUERY_FAILED',
    'CONTEXT_INVALID', 'CLAIM_REJECTED', 'UPSTREAM_SOCKET_FAILED',
    'SET_RECORDS_FAILED', 'CONNECT_FAILED', 'SSH_AUTH_FAILED',
    'CHANNEL_FAILED', 'REVOKED',
)


def decide(gates):
    if len(gates) != 11 or any(type(x) is not bool for x in gates):
        raise ValueError('requires exactly 11 Boolean gates')
    fail = next((i for i, v in enumerate(gates) if not v), None)
    outcome = 'CONDITIONAL_RELAY' if fail is None else STAGES[fail]
    # ATTEMPT, not evidence that the kernel actually consumed a ticket.
    claim_attempted = all(gates[:4])
    set_attempted = all(gates[:6])
    connect_attempted = all(gates[:7])
    return outcome, claim_attempted, set_attempted, connect_attempted


def matrix():
    for gates in itertools.product((False, True), repeat=11):
        mask = sum((1 << i) for i, bit in enumerate(gates) if bit)
        outcome, claim, records, connect = decide(gates)
        yield f'{mask:04X}|{outcome}|{int(claim)}{int(records)}{int(connect)}\n'


def summary():
    content = ''.join(matrix())
    counts = {s: 0 for s in STAGES + ('CONDITIONAL_RELAY',)}
    for line in content.splitlines():
        counts[line.split('|')[1]] += 1
    return {
        'states': len(content.splitlines()),
        'conditional_relay': counts['CONDITIONAL_RELAY'],
        'stage_counts': counts,
        'sha256': hashlib.sha256(content.encode('ascii')).hexdigest(),
        'scope': 'SYNTHETIC_SEQUENTIAL_MODEL_NOT_WIN32_EXECUTION',
        'kernel_origin_proof': False, 'no_direct_proof': False,
    }

if __name__ == '__main__':
    print(json.dumps(summary(), sort_keys=True))
