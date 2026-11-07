#!/usr/bin/env python3
"""R10: read-only audit of pinned historical WFP classify-drop marginal counts.

This tool neither opens a socket nor calls Windows APIs; never opens or
executes the archived PE. It reads a SHA-pinned, already-redacted historical
Windows JSON, checks numeric consistency and computes mathematically valid
joint-evidence bounds. Joint and kernel ownership proof are ALWAYS false.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

# R9 independently checked the originating GitHub artifact archive & nested PE.
# This is the SHA256 of its *extracted redacted diagnostic JSON*, not a new OS run.
DIAGNOSTIC_SHA256 = 'ad1341b53b8cac676394877a1b5f28cf6e42ebd527ba9fdb89d39e460ce17039'
SOURCE_MERGE = 'ab6ed5273db6e9741915a96c74809433af125870'
ARCHIVE_SHA256 = '95560460776b802da5ccd1a608495609715144a59a7fac5fbfaed331542faa92'
MAX_INPUT = 128 * 1024

MATCH_KEYS = (
    'selected_event_appid_matches',
    'other_event_appid_matches',
    'python_event_appid_matches',
    'agent_event_appid_matches',
    'other_or_unresolved_event_appid',
    'exact_filter_events_without_appid',
    'selected_native_handle_path_event_matches',
    'selected_canonical_handle_appid_event_matches',
    'other_native_handle_path_event_matches',
    'other_canonical_handle_appid_event_matches',
    'selected_basename_only_matches',
    'other_basename_only_matches',
    'selected_appid_ascii_case_only_matches',
    'event_appid_utf16_path_shape_valid',
    'unrelated_filter_classify_drops_same_port',
)


class InvalidEvidence(ValueError):
    """Only constant identifiers (never arbitrary input) reach stdout."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise InvalidEvidence(reason)


def strict_object(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        require(key not in obj, 'duplicate_json_key')
        obj[key] = value
    return obj


def pinned_diagnostic(path: Path) -> dict:
    with path.open('rb') as stream:
        data = stream.read(MAX_INPUT + 1)
    require(len(data) <= MAX_INPUT, 'oversize_diagnostic')
    require(hashlib.sha256(data).hexdigest() == DIAGNOSTIC_SHA256,
            'diagnostic_digest_mismatch')
    d = json.loads(data.decode('utf-8-sig'), object_pairs_hook=strict_object)
    require(type(d) is dict, 'expected_json_object')
    return d


def count(event: dict, key: str, bound: int) -> int:
    value = event.get(key)
    require(type(value) is int and 0 <= value <= bound, 'invalid_marginal_count')
    return value


def intersection_bounds(total: int, a: int, b: int) -> tuple[int, int]:
    """Frechet bounds for sets within a shared N-event universe.

    A count of '1 path match' and '1 AppId match' among three records does
    NOT establish that these matches occurred on the same record.
    """
    require(type(total) is int and 0 < total <= 256, 'invalid_event_universe')
    for n in (a, b):
        require(type(n) is int and 0 <= n <= total, 'invalid_marginal_count')
    return max(0, a + b - total), min(a, b)


def analyze_event(event: dict) -> dict:
    require(type(event) is dict, 'event_record_missing')
    require(event.get('kind') == 'read_only_wfp_exact_filter_drop_correlation',
            'wrong_event_kind')
    for key in ('query_succeeded', 'active_qa_filter_verified',
                'event_collection_proven', 'file_handle_native_identity_compared',
                'filter_id_redacted', 'read_only', 'redacted'):
        require(event.get(key) is True, 'event_positive_gate_not_met')
    for key in ('release_accepted', 'kernel_packet_owner_bound',
                'protected_fail_closed', 'filter_or_auditing_changed',
                'event_appid_expected_source_identity_complete',
                'selected_input_appid_equals_handle_canonical',
                'other_input_appid_equals_handle_canonical'):
        require(event.get(key) is False, 'event_negative_gate_changed')
    total = event.get('exact_qa_filter_classify_drops')
    require(type(total) is int and 0 < total <= 256, 'invalid_event_universe')
    require(event.get('bounded_scan_max') == 256,
            'unrecognized_enumeration_limit')
    c = {k: count(event, k, total) for k in MATCH_KEYS}
    partition = sum(c[k] for k in (
        'selected_event_appid_matches', 'other_event_appid_matches',
        'python_event_appid_matches', 'agent_event_appid_matches',
        'other_or_unresolved_event_appid', 'exact_filter_events_without_appid'))
    require(partition == total, 'nonexhaustive_primary_partition')
    require(c['event_appid_utf16_path_shape_valid'] <=
            total - c['exact_filter_events_without_appid'], 'invalid_unicode_count')
    require(c['selected_event_appid_matches'] == 0 and
            c['other_event_appid_matches'] == 0, 'unexpected_input_appid_match')
    # The two handle-derived boolean predicates share the event universe but
    # are NOT supplied as a per-event conjunction by the existing Rust report.
    pair = {}
    for name in ('selected', 'other'):
        path_count = c[f'{name}_native_handle_path_event_matches']
        app_count = c[f'{name}_canonical_handle_appid_event_matches']
        lower, upper = intersection_bounds(total, path_count, app_count)
        pair[name] = {
            'native_path_marginal': path_count,
            'handle_appid_marginal': app_count,
            'same_event_joint_lower': lower,
            'same_event_joint_upper': upper,
            'same_event_joint_observed': False,
        }
    require(c['python_event_appid_matches'] > 0, 'expected_python_comparator_missing')
    return {
        'exact_filter_classify_drop_events': total,
        'original_selected_input_appid_event_matches': 0,
        'original_other_input_appid_event_matches': 0,
        'python_original_appid_event_matches': c['python_event_appid_matches'],
        'unattributed_to_original_comparators': c['other_or_unresolved_event_appid'],
        'marginal_pairs': pair,
        'same_event_joint_pairs_proved': 0,
        'same_event_joint_pairs_possible_upper': sum(
            pair[k]['same_event_joint_upper'] for k in pair),
        'kernel_pid_creation_epoch_proved': False,
        'accepted_socket_redirect_receipt_proved': False,
        'ndisrd_packetbound_proved': False,
        'system_no_direct_proved': False,
        'release_accepted': False,
    }


def analyze_report(d: dict) -> dict:
    require(d.get('source_commit') == SOURCE_MERGE, 'source_merge_changed')
    require(d.get('kind') == 'original_rust_real_wfp_dynamic_qa_diagnostic_matrix',
            'unexpected_report_kind')
    require(d.get('passed') is True, 'historical_job_not_passed')
    for key in ('release_accepted', 'arbitrary_packet_pid_bound',
                'crash_persistent_fail_closed', 'dns_leak_free', 'win10_11_acceptance'):
        require(d.get(key) is False, 'release_safety_flag_changed')
    identity = d.get('app_id_lookup_consistency')
    require(type(identity) is dict, 'identity_diagnostic_missing')
    for name in ('selected_input_equals_handle_appid',
                 'different_input_equals_handle_appid',
                 'selected_running_image_equals_handle',
                 'different_running_image_equals_handle'):
        require(identity.get(name) is False, 'identity_observation_changed')
    local = d.get('local_interface_ipv4_diagnostic')
    require(type(local) is dict and local.get('tested') is True and
            local.get('same_host_local_delivery_only') is True and
            local.get('actual_external_network_traffic') is False,
            'local_delivery_scope_changed')
    return {
        'ok': True,
        'evidence_kind': 'offline_analysis_of_SHA_pinned_historical_Windows_marginals',
        'historical_source_merge': SOURCE_MERGE,
        'historical_artifact_sha256': ARCHIVE_SHA256,
        'diagnostic_sha256': DIAGNOSTIC_SHA256,
        'loopback': analyze_event(d.get('read_only_net_event_appid_correlation')),
        'same_host_ipv4': analyze_event(local.get('read_only_net_event_appid_correlation')),
        'joint_proof_from_marginals': False,
        'exact_filter_is_not_process_epoch': True,
        'new_native_windows_execution': False,
        'driver_or_filter_changed': False,
        'kernel_origin_connection_identity_proved': False,
        'kernel_process_epoch_proved': False,
        'redirect_socket_receipt_chain_proved': False,
        'ipv6_and_udp_dns_guard_proved': False,
        'ssh_wfp_loss_no_direct_proved': False,
        'ndisrd_packetbound_proved': False,
        'release_accepted': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pinned_diagnostic', type=Path)
    args = parser.parse_args()
    try:
        output = analyze_report(pinned_diagnostic(args.pinned_diagnostic))
    except InvalidEvidence as exc:
        output = {'ok': False, 'error': str(exc), 'release_accepted': False}
    except Exception:
        output = {'ok': False, 'error': 'offline_audit_failed', 'release_accepted': False}
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output['ok'] else 2


if __name__ == '__main__':
    sys.exit(main())
