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

def validate(doc:dict) -> None:
    assert doc.get('kind')==KIND and doc.get('apply_permitted') is False
    assert doc.get('release_accepted') is False and doc.get('no_direct_proved') is False
    fs=doc['filters']; assert len(fs)==4
    assert {f['name'] for f in fs}=={'selected_tcp_v4','selected_tcp_v6','selected_udp_v4','selected_udp_v6'}
    assert {f['protocol'] for f in fs}=={'TCP','UDP'}
    for f in fs:
        assert f['app_condition']=='ALE_ORIGINAL_APP_ID'
        assert f['app_match']=='EXACT_PINNED_BINARY_BLOB_NOT_PROVIDED'
        assert f['permit_if_callout_unregistered'] is False
        assert f['native_hit_proof'] is False
        assert f['lifetime']=='PERSISTENT_CANDIDATE'
        assert 'EXCEPTION_PROVED' not in f['redirect_exception']
    assert doc['boot_time_filter']['flag']=='BOOTTIME_ONLY'
    assert doc['boot_time_filter']['pair_transition_proved'] is False
    assert doc['native_accepted_socket_to_ssh_proved'] is False

if __name__ == '__main__':
    d=build();validate(d)
    print(json.dumps(d,ensure_ascii=False,indent=2,sort_keys=True))
