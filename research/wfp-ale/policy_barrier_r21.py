"""R21 offline impossibility witness for WFP ALE policy-commit-as-barrier.

This module does NOT access Win32, WFP, network, drivers, or the OS firewall.
Its simulated events are NOT authenticated evidence. It asks only what can be
*logically inferred* from observable management snapshots.
"""
from dataclasses import dataclass
from itertools import product

FAMILIES = (4, 6)
TRANSPORTS = ("TCP", "UDP")
OWNERS = ("selected", "sibling", "system_dns")
LIFETIMES = ("same_epoch", "reused_pid_new_epoch")
TUPLES = ("fresh_tuple", "reused_5tuple")
LOSSES = ("none", "transient_ssh_between_polls", "transient_wfp_between_polls")

@dataclass(frozen=True)
class ManagementView:
    """Information user mode can see without an origin-bound classify event."""
    commit_ok: bool
    filter_enumerated: bool
    current_wfp_poll_ok: bool
    current_ssh_poll_ok: bool
    family: int
    transport: str
    local_tuple: str

@dataclass(frozen=True)
class World:
    view: ManagementView
    owner: str
    lifecycle: str
    tuple_history: str
    loss_history: str
    # Hidden variables, deliberately absent from ManagementView.
    post_commit_reauth_delivered: bool
    reauth_block_verdict: bool

    @property
    def all_existing_flows_revalidated(self):
        # Only for the one tracked synthetic flow; NOT a global leak claim.
        return self.post_commit_reauth_delivered and self.reauth_block_verdict


def observational_pair(family, transport, owner, lifecycle, tuple_history, loss):
    """Two distinguishable kernel histories with identical management view."""
    if family not in FAMILIES or transport not in TRANSPORTS:
        raise ValueError("family/transport")
    view = ManagementView(True, True, True, True, family, transport,
                          "[2001:db8::2]:443" if family == 6 else "192.0.2.2:443")
    common = (view, owner, lifecycle, tuple_history, loss)
    revalidated = World(*common, True, True)
    still_pending = World(*common, False, False)
    assert revalidated.view == still_pending.view
    assert revalidated.all_existing_flows_revalidated != still_pending.all_existing_flows_revalidated
    return revalidated, still_pending


def all_pairs():
    for args in product(FAMILIES, TRANSPORTS, OWNERS, LIFETIMES, TUPLES, LOSSES):
        yield observational_pair(*args)


def can_infer_post_commit_barrier(view):
    """Management commit+snapshot is NOT a per-flow reauth acknowledgment."""
    if not isinstance(view, ManagementView):
        raise TypeError("management-view-only")
    return False

@dataclass(frozen=True)
class Flow:
    # All fields are *synthetic* event labels and must not be joined by tuple.
    source_event_token: int
    session: int
    pid: int
    creation_epoch: int
    appid: bytes
    family: int
    transport: str
    tuple: str

@dataclass(frozen=True)
class Auth:
    source_event_token: int
    session: int
    pid: int
    creation_epoch: int
    appid: bytes | None
    family: int
    transport: str
    tuple: str
    policy_epoch: int
    is_reauthorize: bool
    action: str
    from_kernel_event: bool
    fields_known: bool


def event_bound_observation(flow, event, current_policy_epoch):
    """Synthetic per-flow witness only; it cannot authenticate kernel origin."""
    return (current_policy_epoch > 0
            and event.policy_epoch == current_policy_epoch
            and event.is_reauthorize
            and event.action == "BLOCK"
            and event.from_kernel_event
            and event.fields_known and event.appid is not None
            and flow.source_event_token != 0
            and flow.source_event_token == event.source_event_token
            and flow.session == event.session
            and flow.pid != 0 and flow.pid == event.pid
            and flow.creation_epoch != 0 and flow.creation_epoch == event.creation_epoch
            and flow.appid != b"" and flow.appid == event.appid
            and flow.family in FAMILIES and flow.family == event.family
            and flow.transport == event.transport
            and flow.tuple == event.tuple)


def global_no_direct_proved(*_):
    """Not expressible from the supplied evidence; no kernel packet proof."""
    return False


def policy_object_after_owner_exit(lifetime, session_ended):
    """Only documented object lifetime facts; not a packet verdict.

    WFP dynamic-session objects are automatically removed when the session
    ends. Static/persistent policy is not enough by itself to establish
    traffic enforcement under service/BFE failure, hence UNKNOWN.
    """
    if lifetime not in ('dynamic','static','persistent'):
        raise ValueError('unknown WFP object lifetime')
    if lifetime == 'dynamic' and session_ended:
        return 'POLICY_OBJECT_REMOVED'
    return 'ENFORCEMENT_UNPROVEN'
