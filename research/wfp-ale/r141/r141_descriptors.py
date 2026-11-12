#!/usr/bin/env python3
"""NON-INSTALLABLE conceptual WFP policy descriptor dossier. No API calls.

Neither numeric GUIDs nor opaque selected AppId are emitted. This is intentionally
not acceptable as an input to Fwpm*Add; a separate authorized lab will need a
reviewed, fully specified implementation with a rescue route.
"""
from __future__ import annotations
import json
from pathlib import Path

KIND = 'NON_INSTALLABLE_DESIGN_ONLY'

def build() -> dict:
    filters = []
    for family in ('v4', 'v6'):
        filters.append(dict(name=f'selected_tcp_{family}', layer=f'ALE_AUTH_CONNECT_{family.upper()}',
            protocol='TCP', app_condition='ALE_ORIGINAL_APP_ID', app_match='EXACT_PINNED_BINARY_BLOB_NOT_PROVIDED',
            lifetime='PERSISTENT_CANDIDATE', action='CALLOUT_TERMINATING_CANDIDATE',
            callout_unregistered_fallback='BLOCK_IF_FILTER_ACTIVE', permit_if_callout_unregistered=False,
            redirect_exception='UNPROVEN_NO_ALLOW_RULE', native_hit_proof=False))
        filters.append(dict(name=f'selected_udp_{family}', layer=f'ALE_AUTH_CONNECT_{family.upper()}',
            protocol='UDP', app_condition='ALE_ORIGINAL_APP_ID', app_match='EXACT_PINNED_BINARY_BLOB_NOT_PROVIDED',
            lifetime='PERSISTENT_CANDIDATE', action='BLOCK_CANDIDATE',
            callout_unregistered_fallback='NOT_APPLICABLE', permit_if_callout_unregistered=False,
            redirect_exception='NO_UDP_TUNNEL_CURRENTLY', native_hit_proof=False))
    return dict(schema=1,kind=KIND,apply_permitted=False,
        provider=dict(service_name='UNSPECIFIED_AND_NOT_AUTHORIZED',auto_start_verified=False,
                      persistent_metadata_verified=False,enabled_at_bfe_start_verified=False),
        sublayer=dict(key='NOT_ALLOCATED',persistent=False,weight_arbitration_proved=False),
        callout=dict(key='NOT_ALLOCATED',persistent=False,kernel_registration_native_proved=False),
        filters=filters,boot_time_filter=dict(separate_object=True,flag='BOOTTIME_ONLY',
                      pair_transition_proved=False,bfe_runtime_outage_coverage_proved=False),
        native_accepted_socket_to_ssh_proved=False,unattended_rollback_proved=False,
        release_accepted=False,no_direct_proved=False)

def _require(ok: bool, code: str) -> None:
    # Python -O strips `assert`: design-only safeguards must remain executable.
    if not ok:
        raise AssertionError(code)


def validate(doc: dict) -> None:
    _require(isinstance(doc, dict), 'descriptor_not_dict')
    _require(doc.get('schema') == 1 and doc.get('kind') == KIND and
             doc.get('apply_permitted') is False, 'design_only_required')
    _require(doc.get('release_accepted') is False and
             doc.get('no_direct_proved') is False, 'release_claim_forbidden')
    fs = doc.get('filters')
    _require(isinstance(fs, list) and len(fs) == 4, 'four_filters_required')
    expected = {
        f'selected_{protocol.lower()}_{family}': (
            f'ALE_AUTH_CONNECT_{family.upper()}', protocol,
            'CALLOUT_TERMINATING_CANDIDATE' if protocol == 'TCP' else 'BLOCK_CANDIDATE',
            'BLOCK_IF_FILTER_ACTIVE' if protocol == 'TCP' else 'NOT_APPLICABLE',
            'UNPROVEN_NO_ALLOW_RULE' if protocol == 'TCP' else 'NO_UDP_TUNNEL_CURRENTLY')
        for family in ('v4', 'v6') for protocol in ('TCP', 'UDP')
    }
    _require(all(isinstance(f, dict) for f in fs), 'filter_not_dict')
    _require({f.get('name') for f in fs} == set(expected), 'filter_names_mismatch')
    for f in fs:
        layer, protocol, action, fallback, exception = expected[f['name']]
        _require((f.get('layer'), f.get('protocol'), f.get('action'),
                  f.get('callout_unregistered_fallback'), f.get('redirect_exception'))
                 == (layer, protocol, action, fallback, exception),
                 'filter_scope_or_action_mismatch:' + f['name'])
        _require(f.get('app_condition') == 'ALE_ORIGINAL_APP_ID' and
                 f.get('app_match') == 'EXACT_PINNED_BINARY_BLOB_NOT_PROVIDED',
                 'app_identity_not_design_only:' + f['name'])
        _require(f.get('permit_if_callout_unregistered') is False and
                 f.get('native_hit_proof') is False and
                 f.get('lifetime') == 'PERSISTENT_CANDIDATE',
                 'unproven_filter_labeled_accepted:' + f['name'])
    boot = doc.get('boot_time_filter')
    _require(isinstance(boot, dict) and boot.get('flag') == 'BOOTTIME_ONLY' and
             boot.get('pair_transition_proved') is False and
             boot.get('bfe_runtime_outage_coverage_proved') is False,
             'boot_proof_unearned')
    _require(doc.get('native_accepted_socket_to_ssh_proved') is False and
             doc.get('unattended_rollback_proved') is False,
             'native_or_rollback_proof_unearned')
    provider, sublayer, callout = doc.get('provider'), doc.get('sublayer'), doc.get('callout')
    _require(isinstance(provider, dict) and isinstance(sublayer, dict) and
             isinstance(callout, dict), 'ownership_descriptor_missing')
    _require(provider.get('service_name') == 'UNSPECIFIED_AND_NOT_AUTHORIZED' and
             provider.get('auto_start_verified') is False and
             provider.get('enabled_at_bfe_start_verified') is False and
             provider.get('persistent_metadata_verified') is False and
             sublayer.get('key') == 'NOT_ALLOCATED' and
             sublayer.get('persistent') is False and
             sublayer.get('weight_arbitration_proved') is False and
             callout.get('key') == 'NOT_ALLOCATED' and
             callout.get('persistent') is False and
             callout.get('kernel_registration_native_proved') is False,
             'descriptors_must_remain_non_installable')

if __name__ == '__main__':
    d=build();validate(d)
    print(json.dumps(d,ensure_ascii=False,indent=2,sort_keys=True))
