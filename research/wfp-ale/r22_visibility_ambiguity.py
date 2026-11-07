"""R22: WFP management inventory non-attribution proof. Pure stdlib; no OS calls.

Never turn management snapshots into packet-owner, filter-owner, or no-DIRECT
claims. These fixtures represent hypothetical valid WFP management metadata.
"""
from dataclasses import dataclass
from itertools import product

CALLOUT_ACTIONS = frozenset(('CALLOUT_TERMINATING', 'CALLOUT_UNKNOWN'))
FAMILIES = (4, 6)
TRANSPORTS = ('TCP', 'UDP', 'DNS_UDP', 'QUIC_UDP')

@dataclass(frozen=True)
class Session:
    session_key: str
    manager_pid: int
    dynamic: bool
    kernel_mode: bool = False

@dataclass(frozen=True)
class Filter:
    filter_key: str
    filter_id: int
    provider_key: str
    family: int
    transport: str
    flags: frozenset[str]
    action: str
    callout_key: str

@dataclass(frozen=True)
class Inventory:
    sessions: tuple[Session, ...]
    filters: tuple[Filter, ...]
    # Separate snapshot epochs are intentionally not a policy/flow barrier.
    session_snapshot_epoch: int
    filter_snapshot_epoch: int
    visibility_complete: bool = False

@dataclass(frozen=True)
class HiddenWorld:
    inventory: Inventory
    filter_creator_session: str
    source_process_epoch: int
    # This field is NOT visible via FWPM_FILTER0.
    def survives_exit(self, ended_session: str) -> bool:
        owners = {x.session_key: x for x in self.inventory.sessions}
        owner = owners[self.filter_creator_session]
        return not (owner.dynamic and self.filter_creator_session == ended_session)


def indistinguishable_worlds(family: int, transport: str, flags=frozenset()):
    """Same session/filter outputs, opposite filter survival after A exits."""
    if family not in FAMILIES or transport not in TRANSPORTS:
        raise ValueError('unsupported_fixture_dimension')
    if set(flags) - {'PERMIT_IF_CALLOUT_UNREGISTERED'}:
        raise ValueError('invalid_dynamic_fixture_flags')
    a = Session('A', 510, True)
    b = Session('B', 520, True)
    f = Filter('filter-X', 57, 'provider-Z', family, transport,
               frozenset(flags), 'CALLOUT_TERMINATING', 'callout-Q')
    view = Inventory((a, b), (f,), 100, 101, False)
    w_a = HiddenWorld(view, 'A', 2001)
    w_b = HiddenWorld(view, 'B', 3003)
    assert w_a.inventory == w_b.inventory
    assert w_a.survives_exit('A') != w_b.survives_exit('A')
    return w_a, w_b


def local_filter_signal(filt: Filter, callout_registered: bool | None) -> str:
    """Only a *single filter* semantic, never OS no-DIRECT or packet verdict."""
    if 'DISABLED' in filt.flags:
        return 'DISABLED_FILTER_NOT_AN_ACTIVE_BLOCK_PROOF'
    if (filt.action in CALLOUT_ACTIONS
            and 'PERMIT_IF_CALLOUT_UNREGISTERED' in filt.flags
            and callout_registered is False):
        return 'THIS_FILTER_TREATED_AS_PERMIT_IF_CALLOUT_MISSING'
    if callout_registered is None:
        return 'UNKNOWN_CALLOUT_STATE'
    return 'NO_SAFETY_INFERENCE_FROM_THIS_FILTER'


def certify_no_direct(view: Inventory, *, policy_committed: bool,
                      selected_appid_known: bool, kernel_receipt: bool) -> bool:
    """No management inventory (including a hypothetical receipt flag) suffices.

    Caller-supplied `kernel_receipt=True` is not authenticated, and a snapshot
    omits origin-bound packet evidence, WFP reauthorization and all traffic.
    """
    if not isinstance(view, Inventory):
        raise TypeError('inventory_required')
    return False


def enumerate_indistinguishable_pairs():
    for family, transport, flags in product(FAMILIES, TRANSPORTS,
            (frozenset(), frozenset({'PERMIT_IF_CALLOUT_UNREGISTERED'}))):
        yield indistinguishable_worlds(family, transport, flags)


def counts():
    pairs = list(enumerate_indistinguishable_pairs())
    return {'indistinguishable_pairs': len(pairs),
            'different_hidden_survival': sum(a.survives_exit('A') != b.survives_exit('A')
                                             for a, b in pairs),
            'source': 'synthetic_management_snapshots',
            'native_windows_executed': False,
            'filter_to_session_mapping_proved': False,
            'packet_bound': False,
            'g2_pass': False,
            'system_no_direct_proved': False}

if __name__ == '__main__':
    import json
    print(json.dumps(counts(), indent=2))
