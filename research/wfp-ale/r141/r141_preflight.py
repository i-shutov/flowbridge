#!/usr/bin/env python3
"""R141: no-write WFP persistence design preflight. No WFP API is invoked.

A positive outcome means design dossier readiness for independent LAB REVIEW,
never runtime filtering, OS fail-closed or release acceptance.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass
import json

@dataclass(frozen=True)
class Candidate:
    lifetime: str = 'dynamic'
    provider_persistent: bool = False
    sublayer_persistent: bool = False
    callout_persistent: bool = False
    filter_persistent: bool = False
    provider_service_auto_start: bool = False
    provider_enabled_after_bfe_start: bool = False
    permit_if_callout_unregistered: bool = False
    selected_app_v4_tcp: bool = False
    selected_app_v6_tcp: bool = False
    selected_app_v4_udp: bool = False
    selected_app_v6_udp: bool = False
    dns_indirect_origin_accounted: bool = False
    hard_block_without_proven_exception: bool = False
    path_or_pid_only_exception: bool = False
    provenance_bound_exception_design_reviewed: bool = False
    sublayer_arbitration_reviewed: bool = False
    native_bfe_restart_test_plan: bool = False
    native_boot_transition_test_plan: bool = False
    independent_recovery_and_rollback_plan: bool = False
    accepted_socket_to_ssh_evidence_plan: bool = False

BLOCKERS=(
    'lifetime_not_persistent',
    'provider_not_persistent',
    'sublayer_not_persistent',
    'callout_not_persistent',
    'filter_not_persistent',
    'provider_startup_unproven',
    'provider_activation_unproven',
    'fail_open_when_callout_missing',
    'selected_tcp_ipv4_not_covered',
    'selected_tcp_ipv6_not_covered',
    'selected_udp_ipv4_not_covered',
    'selected_udp_ipv6_not_covered',
    'out_of_process_dns_unaccounted',
    'hard_block_can_break_redirect',
    'path_or_pid_only_exception_unsafe',
    'native_provenance_exception_not_reviewed',
    'wfp_filter_arbitration_not_reviewed',
    'runtime_bfe_stop_test_missing',
    'boot_to_bfe_handoff_test_missing',
    'out_of_band_recovery_plan_missing',
    'accepted_socket_ssh_proof_plan_missing',
)

def evaluate(c: Candidate) -> dict:
    if not isinstance(c, Candidate):
        raise TypeError('Candidate required')
    if type(c.lifetime) is not str or c.lifetime not in ('dynamic','static','persistent','boot_time'):
        raise ValueError('unknown lifetime')
    for field in Candidate.__dataclass_fields__:
        if field != 'lifetime' and type(getattr(c, field)) is not bool:
            raise TypeError('boolean required: '+field)
    tests=(
        c.lifetime != 'persistent',
        not c.provider_persistent,
        not c.sublayer_persistent,
        not c.callout_persistent,
        not c.filter_persistent,
        not c.provider_service_auto_start,
        not c.provider_enabled_after_bfe_start,
        c.permit_if_callout_unregistered,
        not c.selected_app_v4_tcp,
        not c.selected_app_v6_tcp,
        not c.selected_app_v4_udp,
        not c.selected_app_v6_udp,
        not c.dns_indirect_origin_accounted,
        c.hard_block_without_proven_exception,
        c.path_or_pid_only_exception,
        not c.provenance_bound_exception_design_reviewed,
        not c.sublayer_arbitration_reviewed,
        not c.native_bfe_restart_test_plan,
        not c.native_boot_transition_test_plan,
        not c.independent_recovery_and_rollback_plan,
        not c.accepted_socket_to_ssh_evidence_plan,
    )
    reasons=[name for name,blocked in zip(BLOCKERS,tests,strict=True) if blocked]
    return dict(schema=1,status='NOT_DEPLOYABLE' if reasons else 'DOSSIER_READY_FOR_INDEPENDENT_LAB_REVIEW_ONLY',
                blockers=reasons,release_accepted=False,
                native_wfp_executed=False,no_direct_proved=False,
                bfe_down_continuity_proved=False,
                candidate=asdict(c))

def r19_source_snapshot() -> Candidate:
    """Source-pinned R19, not a native BFE inspection."""
    return Candidate(selected_app_v4_tcp=True,selected_app_v6_tcp=True)

def naive_persistent_block() -> Candidate:
    """Deliberate anti-pattern: persistent hard BLOCK with no safe redirect path."""
    return Candidate(lifetime='persistent',provider_persistent=True,sublayer_persistent=True,
                     callout_persistent=True,filter_persistent=True,
                     provider_service_auto_start=True,provider_enabled_after_bfe_start=True,
                     selected_app_v4_tcp=True,selected_app_v6_tcp=True,
                     hard_block_without_proven_exception=True,path_or_pid_only_exception=True)

if __name__ == '__main__':
    print(json.dumps({'r19_source_snapshot':evaluate(r19_source_snapshot()),
                      'naive_persistent_block':evaluate(naive_persistent_block())},indent=2))
