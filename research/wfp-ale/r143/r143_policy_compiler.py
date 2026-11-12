#!/usr/bin/env python3
"""R143: offline, deliberately NON-INSTALLABLE WFP policy blueprint compiler.

Input is the hash-pinned R141 design-only JSON from this repository. Output is
symbolic metadata, a dependency DAG, and a model state graph. It contains NO
real GUID/AppId/filter flags/binary payload/WFP install or delete instructions.
Python -O does not disable validation. Even a simulated 'ready' state does NOT
represent native filtering, runtime WFP permission, or a RELEASE decision.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
R141 = ROOT.parent / "r141" / "R141_DESIGN_ONLY_DESCRIPTORS.json"
R141_SHA256 = "28c86cdaabeae107ca9ddfb95097622d940eee2ea454cf04edb781d52bb3c289"
KIND = "NON_INSTALLABLE_POLICY_BLUEPRINT"
INPUT_KIND = "NON_INSTALLABLE_DESIGN_ONLY"

# Each bit is an untrusted *simulated* observation, not a WFP authorization.
READY_OBSERVATIONS = (
    "selected_image_pinned", "provider_persistent", "sublayer_persistent",
    "callout_persistent", "filter_persistent", "provider_auto_start",
    "kernel_callout_registered", "bfe_active", "independent_direct_block_observed",
    "accepted_socket_wfp_receipt_verified", "ssh_authenticated",
)
ALL_READY = (1 << len(READY_OBSERVATIONS)) - 1
PHASES = ("BLOCKING_BASELINE", "VERIFIED_REDIRECT_READY", "REVOKING", "RECOVERY")
FAILURES = ("BROKER_LOSS", "SSH_LOSS", "DRIVER_LOSS", "BFE_LOSS",
            "POLICY_OBJECT_LOSS", "REAUTHPROVENANCE_LOSS", "WFP_RIGHTS_MISMATCH")
EVENTS = ("ASSEMBLE", "WITNESS_READY", "REVOKE_COMPLETE", "RECOVER_BASELINE", "RESTART", *FAILURES)

class GateError(ValueError):
    pass

def need(condition: bool, code: str) -> None:
    if type(condition) is not bool or not condition:
        raise GateError(code)

def strict_pairs(pairs: list[tuple[str, Any]]) -> dict:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise GateError("duplicate_json_key:" + key)
        value[key] = item
    return value

def strict_load(raw: bytes) -> Any:
    need(len(raw) <= 65536, "input_too_large")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(GateError("nonfinite_number:" + x)))
    except UnicodeError as exc:
        raise GateError("not_utf8") from exc
    except json.JSONDecodeError as exc:
        raise GateError("invalid_json") from exc

def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       indent=2, separators=(",", ": "), allow_nan=False) + "\n").encode("utf-8")

def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

def reference() -> dict:
    raw = R141.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == R141_SHA256, "r141_reference_hash_drift")
    obj = strict_load(raw)
    validate_input(obj, obj)
    return obj

def same_typed(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(
            same_typed(left[k], right[k]) for k in right)
    if type(left) is list:
        return len(left) == len(right) and all(
            same_typed(x, y) for x, y in zip(left, right, strict=True))
    return left == right

def validate_input(doc: Any, pinned_reference: dict) -> None:
    need(type(doc) is dict, "input_not_object")
    need(type(pinned_reference) is dict, "reference_not_object")
    # Exact structural schema. No extra nested fields, privilege promotions,
    # substituted AppId, executable paths, arbitrary GUIDs or fallback flags.
    need(same_typed(doc, pinned_reference), "dossier_drift_or_mutation")
    need(type(doc.get("schema")) is int and doc["schema"] == 1, "bad_schema")
    need(doc.get("kind") == INPUT_KIND, "wrong_source_kind")
    for flag in ("apply_permitted", "release_accepted", "no_direct_proved",
                 "native_accepted_socket_to_ssh_proved", "unattended_rollback_proved"):
        need(doc.get(flag) is False, "unearned_authority:" + flag)
    fs = doc.get("filters")
    need(type(fs) is list and len(fs) == 4, "bad_rule_count")
    expected = [(fam, proto) for fam in ("v4", "v6") for proto in ("tcp", "udp")]
    for f, (family, protocol) in zip(fs, expected, strict=True):
        need(type(f) is dict and f.get("name") == f"selected_{protocol}_{family}", "swapped_rule")
        need(f.get("layer") == f"ALE_AUTH_CONNECT_{family.upper()}", "swapped_wfp_layer")
        need(f.get("protocol") == protocol.upper(), "swapped_protocol")
        need(f.get("app_condition") == "ALE_ORIGINAL_APP_ID", "original_appid_required")
        need(f.get("app_match") == "EXACT_PINNED_BINARY_BLOB_NOT_PROVIDED", "opaque_identity_missing")
        need(f.get("lifetime") == "PERSISTENT_CANDIDATE", "lifetime_not_design_candidate")
        need(f.get("native_hit_proof") is False and
             f.get("permit_if_callout_unregistered") is False, "unearned_filter_proof")
        if protocol == "tcp":
            need(f.get("action") == "CALLOUT_TERMINATING_CANDIDATE" and
                 f.get("callout_unregistered_fallback") == "BLOCK_IF_FILTER_ACTIVE" and
                 f.get("redirect_exception") == "UNPROVEN_NO_ALLOW_RULE", "unsafe_tcp_action")
        else:
            need(f.get("action") == "BLOCK_CANDIDATE" and
                 f.get("callout_unregistered_fallback") == "NOT_APPLICABLE" and
                 f.get("redirect_exception") == "NO_UDP_TUNNEL_CURRENTLY", "unsafe_udp_action")
    need(doc.get("boot_time_filter", {}).get("pair_transition_proved") is False, "boot_handoff_unproven")

def model_ready(mask: int) -> bool:
    need(type(mask) is int and 0 <= mask <= ALL_READY, "invalid_model_mask")
    return mask == ALL_READY

def model_matrix() -> str:
    # Compiled blueprint models MAY simulate all observations; this still never
    # changes native_proof/release_accepted flags of any compiled artifact.
    return "".join(f"{mask:04d}|{int(model_ready(mask))}\n" for mask in range(ALL_READY + 1))

def transition(phase: str, event: str, readiness_mask: int = 0,
               independently_observed_baseline: bool = False) -> dict:
    need(phase in PHASES, "unknown_phase")
    need(event in EVENTS, "unknown_event")
    model_ready(readiness_mask)  # performs type and range validation
    need(type(independently_observed_baseline) is bool, "baseline_must_be_boolean")
    nxt = phase
    reason = "NO_CHANGE"
    continuity_unknown = False
    if event == "BFE_LOSS":
        # No claim that persistent objects continue to enforce during runtime BFE loss.
        nxt, reason, continuity_unknown = "RECOVERY", "BFE_OUTAGE_NO_CONTINUITY_PROOF", True
    elif event in FAILURES:
        nxt, reason = "REVOKING", "INVALIDATION_REQUIRES_NATIVE_ENFORCEMENT"
    elif event == "RESTART":
        nxt, reason = "RECOVERY", "RESTART_REQUIRES_FRESH_EVIDENCE"
    elif event == "ASSEMBLE" and phase == "BLOCKING_BASELINE":
        nxt, reason = "RECOVERY", "PREPARE_ONLY_NO_FILTER_INSTALL"
    elif event == "WITNESS_READY":
        if phase == "RECOVERY" and model_ready(readiness_mask):
            nxt, reason = "VERIFIED_REDIRECT_READY", "SYNTHETIC_CONDITIONAL_READY_NOT_NATIVE_PROOF"
        else:
            nxt, reason = phase, "INCOMPLETE_PROVENANCE_OR_WRONG_PHASE"
    elif event in ("REVOKE_COMPLETE", "RECOVER_BASELINE"):
        if phase in ("REVOKING", "RECOVERY") and independently_observed_baseline:
            nxt, reason = "BLOCKING_BASELINE", "SIMULATED_BASELINE_OBSERVATION_ONLY"
        else:
            nxt, reason = "RECOVERY", "UNVERIFIED_BASELINE_MUST_NOT_BE_CLAIMED"
    return {
        "from": phase, "event": event, "to": nxt, "reason": reason,
        "continuity_unknown": continuity_unknown,
        "actual_enforcement_proved": False, "release_accepted": False,
    }

def object_graph(doc: dict) -> list[dict]:
    # Symbolic references are intentionally unusable as WFP GUIDs.
    nodes = [
        {"symbol": "DESIGN_PROVIDER", "kind": "provider", "depends_on": [],
         "lifetime": "PERSISTENT_REVIEW_CANDIDATE", "service_name": "UNSPECIFIED",
         "native_status": "NOT_PROVED"},
        {"symbol": "DESIGN_SUBLAYER", "kind": "sublayer", "depends_on": ["DESIGN_PROVIDER"],
         "lifetime": "PERSISTENT_REVIEW_CANDIDATE", "arbitration": "UNREVIEWED"},
    ]
    for family in ("v4", "v6"):
        nodes.append({"symbol": f"DESIGN_CALLOUT_{family.upper()}", "kind": "callout",
                      "depends_on": ["DESIGN_PROVIDER", "DESIGN_SUBLAYER"],
                      "registration": "NOT_PROVED", "lifetime": "PERSISTENT_REVIEW_CANDIDATE"})
    for f in doc["filters"]:
        family, proto = f["name"].rsplit("_", 1)[1], f["protocol"]
        deps = ["DESIGN_PROVIDER", "DESIGN_SUBLAYER"]
        if proto == "TCP":
            deps.append(f"DESIGN_CALLOUT_{family.upper()}")
        nodes.append({"symbol": "DESIGN_FILTER_" + f["name"].upper(), "kind": "filter",
                      "depends_on": deps,
                      "family": family, "protocol": proto,
                      "layer": f["layer"], "match": f["app_condition"],
                      "selected_appid": "OPAQUE_APPID_NOT_PROVIDED",
                      "action": f["action"], "lifetime": "PERSISTENT_REVIEW_CANDIDATE",
                      "permit_if_callout_unregistered": False,
                      "native_status": "NOT_PROVED"})
    validate_graph(nodes)
    return nodes

def validate_graph(nodes: list[dict]) -> None:
    need(type(nodes) is list and len(nodes) == 8, "graph_cardinality")
    symbols = ["DESIGN_PROVIDER", "DESIGN_SUBLAYER", "DESIGN_CALLOUT_V4",
               "DESIGN_CALLOUT_V6", "DESIGN_FILTER_SELECTED_TCP_V4",
               "DESIGN_FILTER_SELECTED_UDP_V4", "DESIGN_FILTER_SELECTED_TCP_V6",
               "DESIGN_FILTER_SELECTED_UDP_V6"]
    need([n.get("symbol") if type(n) is dict else None for n in nodes] == symbols,
         "symbolic_order_or_identity_changed")
    seen: set[str] = set()
    for i, node in enumerate(nodes):
        sym = symbols[i]
        need(node.get("lifetime") == "PERSISTENT_REVIEW_CANDIDATE", "graph_lifetime_drift")
        if i == 0:
            need(set(node) == {"symbol", "kind", "depends_on", "lifetime", "service_name", "native_status"}
                 and node["kind"] == "provider" and node["service_name"] == "UNSPECIFIED"
                 and node["native_status"] == "NOT_PROVED" and node["depends_on"] == [],
                 "provider_not_design_only")
        elif i == 1:
            need(set(node) == {"symbol", "kind", "depends_on", "lifetime", "arbitration"}
                 and node["kind"] == "sublayer" and node["arbitration"] == "UNREVIEWED"
                 and node["depends_on"] == ["DESIGN_PROVIDER"], "sublayer_scope_drift")
        elif i in (2, 3):
            need(set(node) == {"symbol", "kind", "depends_on", "registration", "lifetime"}
                 and node["kind"] == "callout" and node["registration"] == "NOT_PROVED"
                 and node["depends_on"] == ["DESIGN_PROVIDER", "DESIGN_SUBLAYER"],
                 "callout_scope_drift")
        else:
            family = "v4" if i in (4, 5) else "v6"
            protocol = "TCP" if i in (4, 6) else "UDP"
            dependencies = ["DESIGN_PROVIDER", "DESIGN_SUBLAYER"]
            if protocol == "TCP": dependencies.append(f"DESIGN_CALLOUT_{family.upper()}")
            need(set(node) == {"symbol", "kind", "depends_on", "family", "protocol", "layer",
                                "match", "selected_appid", "action", "lifetime",
                                "permit_if_callout_unregistered", "native_status"}
                 and node["kind"] == "filter" and node["depends_on"] == dependencies
                 and node["family"] == family and node["protocol"] == protocol
                 and node["layer"] == f"ALE_AUTH_CONNECT_{family.upper()}"
                 and node["match"] == "ALE_ORIGINAL_APP_ID"
                 and node["selected_appid"] == "OPAQUE_APPID_NOT_PROVIDED"
                 and node["action"] == ("CALLOUT_TERMINATING_CANDIDATE" if protocol == "TCP" else "BLOCK_CANDIDATE")
                 and node["permit_if_callout_unregistered"] is False
                 and node["native_status"] == "NOT_PROVED", "filter_compiled_scope_drift")
        for dependency in node["depends_on"]:
            need(dependency in seen, "unresolved_or_cyclic_design_dependency")
        seen.add(sym)

def compile_design(doc: dict, pinned_reference: dict) -> dict:
    validate_input(doc, pinned_reference)
    objects = object_graph(doc)
    result = {
        "schema": 1, "kind": KIND, "source": "R141_PINNED_DESIGN_ONLY",
        "reference_sha256": R141_SHA256,
        "source_structural_sha256": digest(doc),
        "apply_permitted": False, "installer_present": False,
        "real_guids_present": False, "real_selected_appid_present": False,
        "native_wfp_executed": False, "release_accepted": False,
        "no_direct_proved": False, "bfe_outage_continuity_proved": False,
        "redirect_exception_proved": False,
        "graph": objects,
        "provisioning_design_order": [n["symbol"] for n in objects],
        "rollback_design_order": [n["symbol"] for n in reversed(objects)],
        "rollback_executable": False,
        "boot_handoff": {"object_kind": "SEPARATE_BOOT_DESIGN", "persistent_flag_combined": False,
                         "runtime_bfe_restart_coverage": "UNPROVEN"},
        "state_machine": {
            "initial": "BLOCKING_BASELINE", "states": list(PHASES),
            "events": list(EVENTS),
            "ready_requires": list(READY_OBSERVATIONS),
            "ready_observations_proven": False,
            "state_names_are_model_only": True,
        },
        "unresolved": [
            "NATIVE_WFP_ARBITRATION", "BOOT_TO_BFE_HANDOFF",
            "RUNTIME_BFE_OUTAGE", "CALL_OUT_REGISTRATION_AND_STARTUP",
            "CURRENT_VS_ORIGINAL_APPID", "NATIVE_ALE_REAUTHORIZATION",
            "SOCKET_RECORD_CLAIM_SSH", "SELECTED_APP_DNS_AND_QUIC",
            "INDEPENDENT_ROLLBACK", "EXTERNAL_NO_DIRECT_OBSERVER",
        ],
    }
    result["blueprint_sha256"] = digest(result)
    validate_blueprint(result)
    return result

def validate_blueprint(bp: Any) -> None:
    need(type(bp) is dict and bp.get("kind") == KIND and bp.get("schema") == 1, "bad_compiled_type")
    for field in ("apply_permitted", "installer_present", "real_guids_present",
                  "real_selected_appid_present", "native_wfp_executed", "release_accepted",
                  "no_direct_proved", "bfe_outage_continuity_proved", "redirect_exception_proved",
                  "rollback_executable"):
        need(bp.get(field) is False, "unearned_compiled_authority:" + field)
    need(type(bp["schema"]) is int, "compiled_schema_type")
    need(set(bp) == {"schema", "kind", "source", "reference_sha256",
                            "source_structural_sha256", "apply_permitted", "installer_present",
                            "real_guids_present", "real_selected_appid_present", "native_wfp_executed",
                            "release_accepted", "no_direct_proved", "bfe_outage_continuity_proved",
                            "redirect_exception_proved", "graph", "provisioning_design_order",
                            "rollback_design_order", "rollback_executable", "boot_handoff",
                            "state_machine", "unresolved", "blueprint_sha256"}, "unexpected_blueprint_fields")
    need(bp.get("reference_sha256") == R141_SHA256 and bp.get("source") == "R141_PINNED_DESIGN_ONLY",
         "source_pin_changed")
    need(bp.get("source_structural_sha256") == digest(reference()), "source_structure_changed")
    validate_graph(bp.get("graph"))
    syms = [n["symbol"] for n in bp["graph"]]
    need(bp.get("provisioning_design_order") == syms, "wrong_dag_order")
    need(bp.get("rollback_design_order") == list(reversed(syms)), "wrong_rollback_order")
    need(same_typed(bp.get("boot_handoff"), {
        "object_kind": "SEPARATE_BOOT_DESIGN", "persistent_flag_combined": False,
        "runtime_bfe_restart_coverage": "UNPROVEN"}), "invalid_boot_handoff_claim")
    sm = bp.get("state_machine")
    need(type(sm) is dict and same_typed(sm, {"initial": "BLOCKING_BASELINE",
         "states": list(PHASES), "events": list(EVENTS),
         "ready_requires": list(READY_OBSERVATIONS),
         "ready_observations_proven": False, "state_names_are_model_only": True}),
         "state_machine_must_remain_synthetic")
    need(bp.get("unresolved") == [
        "NATIVE_WFP_ARBITRATION", "BOOT_TO_BFE_HANDOFF",
        "RUNTIME_BFE_OUTAGE", "CALL_OUT_REGISTRATION_AND_STARTUP",
        "CURRENT_VS_ORIGINAL_APPID", "NATIVE_ALE_REAUTHORIZATION",
        "SOCKET_RECORD_CLAIM_SSH", "SELECTED_APP_DNS_AND_QUIC",
        "INDEPENDENT_ROLLBACK", "EXTERNAL_NO_DIRECT_OBSERVER",
    ], "unknown_unresolved_release_gates")
    must = bp.get("blueprint_sha256")
    need(type(must) is str and len(must) == 64, "missing_blueprint_fingerprint")
    without = {k: v for k, v in bp.items() if k != "blueprint_sha256"}
    need(digest(without) == must, "blueprint_mutated_after_compilation")
    # Prevent accidental leakage of system operations in the serialized artifact.
    encoded = canonical_bytes(bp)
    for forbidden in (b'FwpmFilterAdd0', b'FwpmEngineOpen0', b'\\\\.\\',
                      b'S-1-5-18', b'GUID::from_u128', b'FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED'):
        need(forbidden not in encoded, "installer_or_sensitive_content_leaked")

def compile_from_bytes(input_raw: bytes | None = None) -> dict:
    pinned = reference()
    source = pinned if input_raw is None else strict_load(input_raw)
    return compile_design(source, pinned)

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="Optional strictly identical R141 dossier JSON")
    parser.add_argument("--output", type=Path, help="Write design-only JSON to this file")
    parser.add_argument("--model-matrix", action="store_true", help="Print 2048 synthetic gate rows")
    args = parser.parse_args()
    if args.model_matrix:
        print(model_matrix(), end="")
        return
    result = compile_from_bytes(args.input.read_bytes() if args.input else None)
    payload = canonical_bytes(result)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    else:
        print(payload.decode("utf-8"), end="")

if __name__ == "__main__":
    main()
