#!/usr/bin/env python3
"""Offline trust-candidate simulator; NO Windows APIs, driver, filters, network.

Same transport endpoint handle across WFP layers is a *candidate correlation*;
never an authenticated connection proof, especially after lifetime reuse.
"""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Owner:
    pid: int
    generation: int
    epoch: int
    app_id: bytes
    exe_identity: bytes
    referenced: bool

@dataclass(frozen=True)
class Redirect:
    ticket: int
    session: int
    endpoint: int
    pid: int
    generation: int
    app_id: bytes
    family: int
    destination: str

@dataclass(frozen=True)
class Authorization:
    endpoint: int
    pid: int
    generation: int
    path_identity: bytes
    family: int
    # A repeated ALE_AUTH_CONNECT may be reauthorization, not new flow proof.
    reauthorize: bool = False

class ResearchGate:
    """Conservative synthetic gate; outputs only MODEL_CANDIDATE, never PROVED.

    Endpoint handle is used as supplementary consistency check; identity is
    the independent pinned owner + ticket + accepted-socket context.
    """
    def __init__(self, selected: bytes, session: int):
        self.selected = selected
        self.session = session
        self.live: dict[int, Owner] = {}
        self.poisoned: set[int] = set()
        self.seen_generations: dict[int, set[int]] = {}
        self.seen_epochs: dict[int, set[int]] = {}
        self.poisoned_endpoints: set[int] = set()
        self.redirects: dict[int, Redirect] = {}
        self.auth: dict[int, Authorization] = {}
        # An AUTH observation is not portable to another pending ticket.
        self.auth_ticket: dict[int, int] = {}
        self.issued: set[int] = set()
        self.consumed: set[int] = set()
        self.retired: set[int] = set()
        self.active_filter = True
        self.active_callout = True
        self.ssh_ready = True

    def _retire_endpoint(self, endpoint: int) -> None:
        # Without a native ALE_ENDPOINT_CLOSURE event and proven lifetime,
        # endpoint reuse is ambiguous for the remainder of this model session.
        self.poisoned_endpoints.add(endpoint)
        self.auth.pop(endpoint, None)
        self.auth_ticket.pop(endpoint, None)
        for ticket, request in tuple(self.redirects.items()):
            if request.endpoint == endpoint:
                self.retired.add(ticket)
                self.redirects.pop(ticket)

    def _revoke_pid_state(self, pid: int) -> None:
        # A classification or AUTH observation must not survive its owner.
        # Numeric endpoint handles are lifetime-scoped; poison them on exit.
        endpoints = {request.endpoint for request in self.redirects.values() if request.pid == pid}
        endpoints.update(endpoint for endpoint, event in self.auth.items() if event.pid == pid)
        for endpoint in endpoints:
            self._retire_endpoint(endpoint)

    def start_process(self, owner: Owner) -> str:
        if owner.pid <= 0 or owner.generation <= 0 or owner.epoch <= 0 or not owner.referenced or not owner.app_id or not owner.exe_identity:
            return 'INVALID_OWNER'
        if owner.pid in self.live or owner.pid in self.poisoned:
            # Overlapping/unknown generation permanently poisons this PID for this session.
            self.poisoned.add(owner.pid)
            self._revoke_pid_state(owner.pid)
            return 'AMBIGUOUS_OWNER'
        if owner.generation in self.seen_generations.get(owner.pid, set()):
            # A reused generation number may alias a *different* creation epoch.
            # The callback's generation is assumed, not a Windows-provided field.
            self.poisoned.add(owner.pid)
            self._revoke_pid_state(owner.pid)
            return 'REUSED_GENERATION'
        if owner.epoch in self.seen_epochs.get(owner.pid, set()):
            # Same numeric epoch is ambiguous, even with a new generation.
            self.poisoned.add(owner.pid)
            self._revoke_pid_state(owner.pid)
            return 'REUSED_EPOCH'
        self.seen_generations.setdefault(owner.pid, set()).add(owner.generation)
        self.seen_epochs.setdefault(owner.pid, set()).add(owner.epoch)
        self.live[owner.pid] = owner
        return 'REGISTERED_MODEL'

    def stop_process(self, pid: int, generation: int) -> str:
        owner = self.live.get(pid)
        if owner is None or owner.generation != generation:
            # Missing/out-of-order exit poisons PID; never silently trust it.
            self.poisoned.add(pid)
            self._revoke_pid_state(pid)
            return 'STALE_EXIT'
        del self.live[pid]
        self._revoke_pid_state(pid)
        return 'REVOKED_MODEL'

    def classify(self, request: Redirect) -> str:
        if not self.active_filter or not self.active_callout:
            return 'UNPROTECTED'
        if request.app_id != self.selected:
            return 'OUTSIDE_SCOPE'
        if request.family not in (4, 6) or not request.destination or request.endpoint <= 0 or request.ticket <= 0 or request.session != self.session:
            return 'INVALID_CLASSIFY'
        if request.endpoint in self.poisoned_endpoints:
            return 'AMBIGUOUS_ENDPOINT'
        owner = self.live.get(request.pid)
        if request.pid in self.poisoned or owner is None or owner.generation != request.generation or owner.app_id != request.app_id:
            return 'UNBOUND_OWNER'
        if request.ticket in self.issued or request.ticket in self.retired:
            return 'REPLAY'
        # A reused endpoint number cannot serve multiple concurrent tickets.
        if request.endpoint in self.auth or any(p.endpoint == request.endpoint for p in self.redirects.values()):
            self._retire_endpoint(request.endpoint)
            return 'AMBIGUOUS_ENDPOINT'
        self.issued.add(request.ticket)
        self.redirects[request.ticket] = request
        return 'CAPTURED_MODEL'

    def observe_auth(self, event: Authorization) -> str:
        if event.endpoint <= 0 or event.family not in (4, 6) or not event.path_identity:
            return 'INVALID_AUTH'
        if event.endpoint in self.poisoned_endpoints:
            return 'AMBIGUOUS_ENDPOINT'
        # Microsoft documents ALE reauthorization, which must not be promoted
        # to a *fresh* connection-owner observation.
        if event.reauthorize:
            return 'REAUTHORIZE_NOT_NEW_PROOF'
        if event.endpoint in self.auth:
            self._retire_endpoint(event.endpoint)
            return 'AMBIGUOUS_ENDPOINT'
        # Bind an AUTH observation to exactly one pending classify in this
        # synthetic model, not merely to a numeric endpoint key.
        pending = [(ticket, request) for ticket, request in self.redirects.items()
                   if request.endpoint == event.endpoint]
        if len(pending) != 1:
            if len(pending) > 1:
                self._retire_endpoint(event.endpoint)
                return 'AMBIGUOUS_ENDPOINT'
            return 'UNBOUND_AUTH'
        ticket, request = pending[0]
        owner = self.live.get(request.pid)
        if (request.pid in self.poisoned or owner is None or not owner.referenced
                or owner.generation != request.generation
                or owner.app_id != request.app_id
                or event.pid != request.pid or event.generation != request.generation
                or event.path_identity != owner.exe_identity
                or event.family != request.family):
            self._retire_endpoint(event.endpoint)
            return 'AMBIGUOUS_ENDPOINT'
        self.auth[event.endpoint] = event
        self.auth_ticket[event.endpoint] = ticket
        return 'SUPPORTING_OBSERVATION_ONLY'

    def accept(self, ticket: int, session: int, endpoint: int, family: int,
               receipt_from_accepted_socket: bool, context_matches: bool,
               outbound_records_set_before_connect: bool) -> str:
        if not self.active_filter or not self.active_callout:
            return 'UNPROTECTED'
        request = self.redirects.pop(ticket, None)
        if request is None or ticket in self.consumed or ticket in self.retired:
            return 'REJECT_INGRESS'
        self.consumed.add(ticket)
        self.retired.add(ticket)
        owner = self.live.get(request.pid)
        # Read only the classified endpoint; never trust a caller-supplied
        # alternate endpoint to choose a different stored AUTH observation.
        supporting = self.auth.get(request.endpoint)
        supporting_ticket = self.auth_ticket.get(request.endpoint)
        self._retire_endpoint(request.endpoint)
        if (session != self.session or request.session != session
                or endpoint != request.endpoint or family != request.family
                or request.pid in self.poisoned or owner is None or owner.generation != request.generation
                or owner.app_id != request.app_id or not owner.referenced
                or supporting is None or supporting_ticket != ticket
                or supporting.pid != owner.pid
                or supporting.generation != owner.generation
                or supporting.path_identity != owner.exe_identity
                or supporting.family != request.family
                or not receipt_from_accepted_socket or not context_matches
                or not outbound_records_set_before_connect or not self.ssh_ready):
            return 'REJECT_INGRESS'
        # Synthetic events cannot prove a real kernel owner. In production, the
        # same classify must pin a genuine referenced EPROCESS and WFP record.
        return 'CONDITIONAL_MODEL_ONLY'

    def loss(self, component: str) -> str:
        if component == 'filter':
            self.active_filter = False
        elif component == 'callout':
            self.active_callout = False
        elif component == 'ssh':
            self.ssh_ready = False
        else:
            return 'UNKNOWN_COMPONENT'
        for endpoint in {req.endpoint for req in self.redirects.values()} | set(self.auth):
            self._retire_endpoint(endpoint)
        return 'UNPROTECTED' if component in ('filter', 'callout') else 'OWNED_INGRESS_CLOSED_ONLY'

    @staticmethod
    def ndisrd_tuple_attribution(*_args: object) -> str:
        return 'NO_PER_FRAME_OWNER_PROOF'


def tests():
    cases = 0
    def eq(actual, expected):
        nonlocal cases
        cases += 1
        assert actual == expected, f'case {cases}: got {actual}, expected {expected}'
    def baseline():
        gate = ResearchGate(b'ntpath:A', 77)
        owner = Owner(501, 1, 901, b'ntpath:A', b'file-object:A', True)
        req = Redirect(9, 77, 700, 501, 1, b'ntpath:A', 4, '192.0.2.10:443')
        evt = Authorization(700, 501, 1, b'file-object:A', 4)
        eq(gate.start_process(owner), 'REGISTERED_MODEL')
        eq(gate.classify(req), 'CAPTURED_MODEL')
        eq(gate.observe_auth(evt), 'SUPPORTING_OBSERVATION_ONLY')
        return gate,owner,req,evt
    for family in (4,6):
        g,o,r,e = baseline()
        if family==6:
            # Separate IPv6 attempt requires matching owner, endpoint and receipt.
            r=Redirect(10,77,701,501,1,b'ntpath:A',6,'[2001:db8::1]:443')
            e=Authorization(701,501,1,b'file-object:A',6)
            eq(g.classify(r),'CAPTURED_MODEL')
            eq(g.observe_auth(e),'SUPPORTING_OBSERVATION_ONLY')
        eq(g.accept(r.ticket,77,r.endpoint,family,True,True,True),'CONDITIONAL_MODEL_ONLY')
        eq(g.accept(r.ticket,77,r.endpoint,family,True,True,True),'REJECT_INGRESS')
    # Termination invalidates pending original even if a new PID process appears.
    g,o,r,e=baseline()
    eq(g.stop_process(501,1),'REVOKED_MODEL')
    eq(g.start_process(Owner(501,2,902,b'ntpath:A',b'file-object:A',True)),'REGISTERED_MODEL')
    eq(g.accept(9,77,700,4,True,True,True),'REJECT_INGRESS')
    # Same PID and same apparent epoch: unique generation is mandatory.
    g,o,r,e=baseline()
    eq(g.stop_process(501,1),'REVOKED_MODEL')
    eq(g.start_process(Owner(501,2,901,b'ntpath:A',b'file-object:A',True)),'REUSED_EPOCH')
    eq(g.classify(r),'AMBIGUOUS_ENDPOINT')
    # Identical tuple can be recycled; no ticket replay.
    g,o,r,e=baseline()
    eq(g.classify(r),'REPLAY')
    eq(g.ndisrd_tuple_attribution(r),'NO_PER_FRAME_OWNER_PROOF')
    # Auth path mismatch cannot borrow endpoint coincidence to authorize.
    g,o,r,e=baseline()
    eq(g.observe_auth(Authorization(700,501,2,b'file-object:B',4)),'AMBIGUOUS_ENDPOINT')
    eq(g.observe_auth(e),'AMBIGUOUS_ENDPOINT')
    eq(g.classify(Redirect(10,77,700,501,1,b'ntpath:A',4,'192.0.2.10:443')),'AMBIGUOUS_ENDPOINT')
    eq(g.accept(9,77,700,4,True,True,True),'REJECT_INGRESS')
    # Missing redirect data; copied record from foreign socket is untrusted.
    for flags in ((False,True,True),(True,False,True),(True,True,False)):
        g,o,r,e=baseline()
        eq(g.accept(9,77,700,4,*flags),'REJECT_INGRESS')
    # Loss of only SSH closes owned ingress, not direct system traffic.
    g,o,r,e=baseline()
    eq(g.loss('ssh'),'OWNED_INGRESS_CLOSED_ONLY')
    eq(g.accept(9,77,700,4,True,True,True),'REJECT_INGRESS')
    for component in ('filter','callout'):
        g,o,r,e=baseline()
        eq(g.loss(component),'UNPROTECTED')
        eq(g.accept(9,77,700,4,True,True,True),'UNPROTECTED')
    # Two same-basename path identities must stay distinct.
    g,o,r,e=baseline()
    eq(g.start_process(Owner(502,1,903,b'ntpath:B',b'file-object:B',True)),'REGISTERED_MODEL')
    eq(g.classify(Redirect(10,77,702,502,1,b'ntpath:B',4,'192.0.2.10:443')),'OUTSIDE_SCOPE')
    # Unmatched endpoint and family cannot be substituted.
    for endpoint,family in ((701,4),(700,6)):
        g,o,r,e=baseline()
        eq(g.accept(9,77,endpoint,family,True,True,True),'REJECT_INGRESS')
    # A duplicate owner-generation notification cannot supplant live reference.
    g,o,r,e=baseline()
    eq(g.start_process(Owner(501,2,902,b'ntpath:A',b'file-object:A',True)),'AMBIGUOUS_OWNER')
    eq(g.stop_process(501,2),'STALE_EXIT')
    eq(g.accept(9,77,700,4,True,True,True),'REJECT_INGRESS')
    # A clean success is a synthetic candidate, NEVER real WFP proof.
    print({'synthetic_assertions_passed':cases, 'native_windows_proof':False,
           'ndisrd_packet_owner_proof':False, 'direct_traffic_protection':False})

if __name__=='__main__':
    tests()
