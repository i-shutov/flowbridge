#!/usr/bin/env python3
"""Independent R7 deterministic negative contract for supplementary AUTH event lifetime.

No Windows APIs or driver/filter/network operations. A MODEL accept is not
kernel-origin WFP proof. This separate audit derives its oracle from a
standalone event-sequence specification and never from the gate's output.
"""
from __future__ import annotations
from itertools import product
import ast
import json
from pathlib import Path
from endpoint_witness_model import Owner, Redirect, Authorization, ResearchGate

APP, FILE = b'ntpath:A', b'file-object:A'
SESSION, PID = 77, 501

def owner(gen=1, epoch=901):
    return Owner(PID, gen, epoch, APP, FILE, True)

def red(ticket=9, endpoint=700, family=4):
    return Redirect(ticket, SESSION, endpoint, PID, 1, APP, family,
                    '192.0.2.10:443' if family == 4 else '[2001:db8::1]:443')

def auth(endpoint=700, family=4, *, reauthorize=False):
    return Authorization(endpoint, PID, 1, FILE, family, reauthorize)

def accept(g, ticket=9, endpoint=700, family=4):
    return g.accept(ticket, SESSION, endpoint, family, True, True, True)

def gate():
    return ResearchGate(APP, SESSION)

def expect(got, expected, label):
    assert got == expected, (label, got, expected)


def main():
    source = (Path(__file__).parent/'endpoint_witness_model.py').read_text(encoding='utf-8')
    ast.parse(source)
    for forbidden in ('ctypes', 'subprocess', 'FwpmFilterAdd0', 'FwpsCalloutRegister'):
        assert forbidden not in source, ('unexpected unsafe/OS bridge', forbidden)
    count = 0
    # Model positives only where unique classify + fresh non-reauthorization
    # matching AUTH + matching receipt are *all present* in this order.
    for family, endpoint, ticket in product((4, 6), (700, 701), (9, 10)):
        g=gate()
        expect(g.start_process(owner()), 'REGISTERED_MODEL', 'register')
        expect(g.classify(red(ticket,endpoint,family)), 'CAPTURED_MODEL','classify')
        expect(g.observe_auth(auth(endpoint,family)), 'SUPPORTING_OBSERVATION_ONLY','fresh auth')
        expect(accept(g,ticket,endpoint,family), 'CONDITIONAL_MODEL_ONLY','bounded conditional')
        expect(accept(g,ticket,endpoint,family), 'REJECT_INGRESS','replay')
        # Same numerical endpoint may not be reused even with another ticket.
        expect(g.classify(red(ticket+100,endpoint,family)), 'AMBIGUOUS_ENDPOINT','endpoint reused')
        count+=3

        # AUTH seen before process creation is not authenticated retroactively.
        g=gate()
        expect(g.observe_auth(auth(endpoint,family)), 'UNBOUND_AUTH','pre-registration auth')
        expect(g.start_process(owner()), 'REGISTERED_MODEL','register after early auth')
        expect(g.classify(red(ticket,endpoint,family)), 'CAPTURED_MODEL','classify after early auth')
        expect(accept(g,ticket,endpoint,family), 'REJECT_INGRESS','reject early auth')
        count+=1

        # A reauthorization event alone is never a new connection proof.
        g=gate()
        expect(g.start_process(owner()),'REGISTERED_MODEL','register reauth')
        expect(g.classify(red(ticket,endpoint,family)), 'CAPTURED_MODEL','classify reauth')
        expect(g.observe_auth(auth(endpoint,family,reauthorize=True)),
               'REAUTHORIZE_NOT_NEW_PROOF','reauthorize')
        expect(accept(g,ticket,endpoint,family), 'REJECT_INGRESS','no initial auth')
        count+=1

        # Two concurrent tickets for one endpoint make the witness ambiguous.
        g=gate()
        expect(g.start_process(owner()),'REGISTERED_MODEL','register overlap')
        expect(g.classify(red(ticket,endpoint,family)),'CAPTURED_MODEL','first classify')
        expect(g.classify(red(ticket+100,endpoint,family)),'AMBIGUOUS_ENDPOINT','overlap')
        expect(g.observe_auth(auth(endpoint,family)),'AMBIGUOUS_ENDPOINT','overlap auth')
        expect(accept(g,ticket,endpoint,family),'REJECT_INGRESS','overlap rejected')
        count+=1

        # Duplicate identical AUTH is not two independent witnesses.
        g=gate()
        expect(g.start_process(owner()),'REGISTERED_MODEL','register duplicate')
        expect(g.classify(red(ticket,endpoint,family)),'CAPTURED_MODEL','classify duplicate')
        expect(g.observe_auth(auth(endpoint,family)),'SUPPORTING_OBSERVATION_ONLY','first auth')
        expect(g.observe_auth(auth(endpoint,family)),'AMBIGUOUS_ENDPOINT','duplicate auth')
        expect(accept(g,ticket,endpoint,family),'REJECT_INGRESS','duplicate reject')
        count+=1

        # An event for the same endpoint but wrong owner/path cannot be patched
        # over by a later matching event.
        g=gate()
        expect(g.start_process(owner()),'REGISTERED_MODEL','register mismatch')
        expect(g.classify(red(ticket,endpoint,family)),'CAPTURED_MODEL','classify mismatch')
        bad=Authorization(endpoint, PID, 1, b'other-file-object',family)
        expect(g.observe_auth(bad),'AMBIGUOUS_ENDPOINT','wrong identity')
        expect(g.observe_auth(auth(endpoint,family)),'AMBIGUOUS_ENDPOINT','no healing')
        expect(accept(g,ticket,endpoint,family),'REJECT_INGRESS','reject corrupted state')
        count+=1

        # Terminated process retires both pending classify and bound AUTH.
        g=gate()
        expect(g.start_process(owner()),'REGISTERED_MODEL','register exit')
        expect(g.classify(red(ticket,endpoint,family)),'CAPTURED_MODEL','classify exit')
        expect(g.observe_auth(auth(endpoint,family)),'SUPPORTING_OBSERVATION_ONLY','auth exit')
        expect(g.stop_process(PID,1),'REVOKED_MODEL','exit')
        expect(accept(g,ticket,endpoint,family),'REJECT_INGRESS','reject exit')
        count+=1

        # Losing SSH/proxy cannot be confused with OS no-DIRECT enforcement.
        g=gate()
        expect(g.start_process(owner()),'REGISTERED_MODEL','register ssh')
        expect(g.classify(red(ticket,endpoint,family)),'CAPTURED_MODEL','classify ssh')
        expect(g.observe_auth(auth(endpoint,family)),'SUPPORTING_OBSERVATION_ONLY','auth ssh')
        expect(g.loss('ssh'),'OWNED_INGRESS_CLOSED_ONLY','ssh loss')
        expect(accept(g,ticket,endpoint,family),'REJECT_INGRESS','ssh ingress')
        count+=1
    print(json.dumps({'ok':True,'negative_cases':count-8,
                      'conditional_only':8,'total_asserted_sequences':count,
                      'independent_specification':True,'native_windows_proof':False,
                      'kernel_owner_proved':False,'ndisrd_packet_bound':False,
                      'os_no_direct_proved':False},sort_keys=True))

if __name__=='__main__': main()
