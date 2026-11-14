"""R185: exact-scope offline WFP filter/control-plane truth-table.

This module NEVER connects to WFP, opens a socket or alters the machine.
Results describe only the selected R19 filter's documented absent-callout
fallback, not total WFP arbitration, enforcement or packet egress.
"""
from itertools import product
import json


def classify(family, selected, tcp, bfe_up, session_alive, registered, kind, permit_if_missing):
    assert family in ('v4', 'v6') and kind in ('redirect', 'auth')
    # R19 has exactly four selected-app TCP filters in one dynamic session.
    scoped = selected and tcp and bfe_up and session_alive
    if not scoped:
        return 'NO_R19_MATCH_OR_BFE_UNAVAILABLE'
    if registered:
        return 'CALLOUT_RUNTIME_UNKNOWN'
    if permit_if_missing:
        return 'FILTER_TREATED_AS_PERMIT'
    # R19: UNKNOWN for REDIRECT, TERMINATING for AUTH; flags==0.
    return 'FILTER_TREATED_AS_BLOCK'


def matrix():
    for f,s,t,b,o,k,kind,p in product(('v4','v6'),(False,True),(False,True),
                                      (False,True),(False,True),(False,True),
                                      ('redirect','auth'),(False,True)):
        yield dict(family=f, selected=s, tcp=t, bfe_up=b,
                   session_alive=o, registered=k, kind=kind,
                   permit_if_missing=p, result=classify(f,s,t,b,o,k,kind,p))


def canonical():
    return ''.join(json.dumps(row, separators=(',',':'), sort_keys=True)+'\n' for row in matrix())


if __name__ == '__main__':
    print(canonical(), end='')
