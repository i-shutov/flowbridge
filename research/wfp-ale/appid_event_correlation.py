#!/usr/bin/env python3
"""Independent offline audit of the EXACT historical Windows WFP AppId event cluster.

No Windows APIs, no drivers/filters, network, binary execution, or archives unpacked
on disk. Every historical measurement stays tied to the exact source and artifacts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import audit_archived_appid as archive_audit


class EvidenceMismatch(ValueError):
    pass


def insist(condition: bool, reason: str) -> None:
    if not condition:
        raise EvidenceMismatch(reason)


def strict_bool(obj: dict, key: str, expected: bool) -> None:
    insist(obj.get(key) is expected, f"flag_{key}_mismatch")


def strict_count(obj: dict, key: str, expected: int) -> None:
    actual = obj.get(key)
    insist(type(actual) is int and actual == expected, f"count_{key}_mismatch")


def evaluate_exact_filter_events(diag: dict) -> dict:
    """The aggregate observation must NOT be promoted to per-event owner proof."""
    insist(diag.get("kind") == "original_rust_real_wfp_dynamic_qa_diagnostic_matrix",
           "unexpected_diagnostic_kind")
    strict_bool(diag, "passed", True)
    strict_bool(diag, "persistent_filter_created", False)
    strict_bool(diag, "arbitrary_packet_pid_bound", False)
    strict_bool(diag, "release_accepted", False)
    # Explicit selected-only enforcement, never a global/cross-platform claim.
    for field in ("app_id_only_trial", "app_id_port_protocol_trial"):
        trial = diag.get(field)
        insist(type(trial) is dict, "trial_absent")
        for k in ("ready", "selected_denied", "different_executable_allowed",
                  "python_allowed", "recovered"):
            strict_bool(trial, k, True)
    port = diag.get("port_only_trial")
    insist(type(port) is dict, "port_only_trial_absent")
    strict_bool(port, "selected_denied", True)
    strict_bool(port, "different_executable_allowed", False)
    strict_bool(port, "python_allowed", False)
    strict_bool(port, "recovered", True)
    identity = diag.get("app_id_lookup_consistency")
    insist(type(identity) is dict, "app_identity_absent")
    for k,v in {
        "selected_self_matches_target":True,
        "different_copy_self_matches_target":False,
        "agent_self_matches_target":False,
        "selected_running_image_equals_handle":False,
        "different_running_image_equals_handle":False,
        "selected_input_equals_handle_appid":False,
        "different_input_equals_handle_appid":False,
    }.items(): strict_bool(identity,k,v)
    event = diag.get("read_only_net_event_appid_correlation")
    insist(type(event) is dict, "event_data_absent")
    insist(event.get("kind") == "read_only_wfp_exact_filter_drop_correlation",
           "unexpected_event_kind")
    for k,v in {
        "query_succeeded":True,
        "active_qa_filter_verified":True,
        "event_collection_proven":True,
        "filter_id_redacted":True,
        "read_only":True,
        "filter_or_auditing_changed":False,
        "file_handle_native_identity_compared":True,
        "kernel_packet_owner_bound":False,
        "event_appid_expected_source_identity_complete":False,
        "release_accepted":False,
    }.items(): strict_bool(event,k,v)
    counters = {
        "exact_qa_filter_classify_drops":3,
        "unrelated_filter_classify_drops_same_port":0,
        "exact_filter_events_without_appid":0,
        "event_appid_utf16_path_shape_valid":3,
        "selected_event_appid_matches":0,
        "other_event_appid_matches":0,
        "python_event_appid_matches":1,
        "agent_event_appid_matches":0,
        "selected_canonical_handle_appid_event_matches":1,
        "other_canonical_handle_appid_event_matches":1,
        "selected_native_handle_path_event_matches":1,
        "other_native_handle_path_event_matches":1,
        "selected_appid_ascii_case_only_matches":0,
        "selected_basename_only_matches":1,
        "other_basename_only_matches":1,
        "python_basename_only_matches":0,
        "agent_basename_only_matches":0,
        "other_or_unresolved_event_appid":2,
    }
    for key,value in counters.items(): strict_count(event,key,value)
    # An aggregate count cannot prove which classifier event matched which source
    # unless per-event evidence is recorded. Preserve that distinction.
    return {
        "historical_windows_appid_events_observed":True,
        "exact_filter_event_count":3,
        "observed_event_appid_shape_valid_count":3,
        "observed_handle_canonical_appid_matches_aggregate":2,
        "observed_input_appid_matches_selected_other_aggregate":0,
        "observed_python_input_appid_matches_aggregate":1,
        "observed_native_handle_path_matches_aggregate":2,
        "selected_appid_policy_denial_observed":True,
        "different_executable_allowed_observed":True,
        "path_spelling_canonicalization_discrepancy":True,
        "exact_per_event_source_partition_verified":False,
        "same_basename_different_dirs_measured":False,
        "alias_matrix_measured":False,
        "process_epoch_bound_to_event":False,
        "packet_pid_bound":False,
        "transparent_redirect_proved":False,
        "native_research_sha_executed":False,
        "release_accepted":False,
    }


def run_on_archive(data: bytes) -> dict:
    # First prove the exact authenticated archive bytes, nested checksums, PE
    # identity, source parentage and never-positive kernel/release flags.
    verified = archive_audit.audit_bytes(data)
    with archive_audit.check_zip(data) as z:
        raw = archive_audit.member(z, "windows-wfp-dynamic-lifecycle.json")
        diagnostic = archive_audit.json_object(raw)
    observed = evaluate_exact_filter_events(diagnostic)
    return {
        "ok":True,
        "source_pr_sha":verified["recorded_source_head"],
        "source_test_merge_sha":verified["recorded_test_merge"],
        "archive_sha256":verified["archive_sha256"],
        "evidence_kind":"audited_historical_windows_exact_filter_events",
        "prior_archive_and_binary_hashes_verified":True,
        "actual_windows_experiment_started_this_cycle":False,
        "observations":observed,
        "release_accepted":False,
    }


def main() -> int:
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("archive",type=Path)
    options=args.parse_args()
    try:
        with options.archive.open("rb") as f:
            data=f.read(archive_audit.MAX_ARCHIVE+1)
        outcome=run_on_archive(data)
    except (archive_audit.AuditError,EvidenceMismatch) as exc:
        outcome={"ok":False,"blocker":str(exc),"release_accepted":False}
    except Exception:
        outcome={"ok":False,"blocker":"archive_or_audit_failed","release_accepted":False}
    print(json.dumps(outcome,indent=2,sort_keys=True))
    return 0 if outcome["ok"] else 2


if __name__=="__main__":
    raise SystemExit(main())
