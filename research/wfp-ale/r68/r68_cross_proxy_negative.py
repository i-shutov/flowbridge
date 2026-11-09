#!/usr/bin/env python3
"""R68: offline source-pinned WFP filter-scope counterexamples, NOT native security proof.

All results are conditional descriptions of *FlowBridge's own two filters*.
UNOBSERVED != PERMIT, BLOCK_REQUESTED != physical block, MODEL_CLAIM != G2 PASS.
"""
from __future__ import annotations
import hashlib
import json
import unittest
from dataclasses import dataclass
from pathlib import Path

KEYS = (
    "original_selected", "current_selected", "tcp", "endpoint_owner_selected",
    "metadata_complete", "epoch_match", "start_key_match", "endpoint_unique",
    "redirect_state_clean", "destination_valid", "target_pid_match",
    "redirected_flag", "ssh_ok", "wfp_ok", "owner_alive_observed",
    "auth_callback_observed",
)
ISSUE_REQUIRE = ("current_selected", "tcp", "endpoint_owner_selected", "metadata_complete",
                 "epoch_match", "start_key_match", "endpoint_unique", "redirect_state_clean",
                 "destination_valid", "ssh_ok", "wfp_ok", "owner_alive_observed")
AUTH_EXTRA = ("original_selected", "target_pid_match", "redirected_flag", "auth_callback_observed")
SCOPE_UDP, SCOPE_NEITHER, SCOPE_REDIRECT_ONLY, SCOPE_AUTH_ONLY, SCOPE_BOTH = range(5)
BASE = (1 << len(KEYS)) - 1
PINS = {
    "research/wfp-ale/kernel-r19/policy_windows.rs": "acf60334320d970f58af3349ee75fbaa59826602",
    "research/wfp-ale/kernel-r19/kernel/src/redirect.rs": "9a07e026134d46ef646d39862bd982cc48bbc5f6",
    "research/wfp-ale/kernel-r19/kernel/src/handoff.rs": "e1d17217db50362ba9c4efc83af820b6beb094cf",
    "research/wfp-ale/kernel-r19/kernel/src/lib.rs": "0af6d4539673d2894cbaa91af0ea8f3524862a26",
}

@dataclass(frozen=True)
class Model:
    family: int
    mask: int
    scope: int
    issue: bool
    attest: bool
    block_requested: bool
    orphan_issue: bool
    auth_without_issue: bool


def bit(mask: int, name: str) -> bool:
    return bool(mask & (1 << KEYS.index(name)))


def classify(family: int, mask: int) -> Model:
    assert family in (4, 6) and 0 <= mask <= BASE
    d = {name: bit(mask, name) for name in KEYS}
    redirect_selected = d["tcp"] and d["current_selected"]
    auth_selected = d["tcp"] and d["original_selected"]
    if not d["tcp"]: scope = SCOPE_UDP
    elif redirect_selected and auth_selected: scope = SCOPE_BOTH
    elif redirect_selected: scope = SCOPE_REDIRECT_ONLY
    elif auth_selected: scope = SCOPE_AUTH_ONLY
    else: scope = SCOPE_NEITHER
    issue = all(d[x] for x in ISSUE_REQUIRE)
    attest = issue and all(d[x] for x in AUTH_EXTRA)
    # Driver calls block(out) if a selected AUTH callback is actually delivered
    # and auth_check cannot create a matching one-time receipt.
    requested_block = auth_selected and d["auth_callback_observed"] and not attest
    return Model(family, mask, scope, issue, attest, requested_block,
                 issue and not auth_selected,
                 auth_selected and d["auth_callback_observed"] and not redirect_selected)


def table() -> dict:
    stats = dict(families=[4, 6], states=0, scope=[0]*5,
                 issue=0, attest=0, block_requested=0, orphan_issue=0,
                 auth_without_issue=0, observed_auth_without_redirect=0,
                 missing_auth_dispatch=0, decision_sha256=None,
                 native_wfp_calls=0, native_packets=0)
    digest = hashlib.sha256()
    for family in (4, 6):
        for mask in range(BASE+1):
            v=classify(family, mask)
            stats["states"] += 1
            stats["scope"][v.scope] += 1
            for name in ("issue", "attest", "block_requested", "orphan_issue", "auth_without_issue"):
                stats[name] += bool(getattr(v, name))
            stats["observed_auth_without_redirect"] += bool(v.scope==SCOPE_AUTH_ONLY and v.block_requested)
            stats["missing_auth_dispatch"] += bool(v.orphan_issue)
            digest.update(f"{family}|{mask}|{v.scope}|{int(v.issue)}|{int(v.attest)}|{int(v.block_requested)}|{int(v.orphan_issue)}|{int(v.auth_without_issue)}\n".encode())
    stats["decision_sha256"] = digest.hexdigest()
    return stats


class NegativeTests(unittest.TestCase):
    def scenario(self, **changes):
        mask=BASE
        for name,value in changes.items():
            mask = (mask | (1 << KEYS.index(name))) if value else (mask & ~(1 << KEYS.index(name)))
        return mask

    def test_families_both_conditions_only_conditional_receipt(self):
        for family in [4,6]:
            v=classify(family, BASE)
            self.assertEqual(v.scope, SCOPE_BOTH)
            self.assertTrue(v.issue and v.attest)
            self.assertFalse(v.block_requested)

    def test_foreign_current_selected_original_never_issues_ticket(self):
        for family in [4,6]:
            v=classify(family, self.scenario(current_selected=False))
            self.assertEqual(v.scope, SCOPE_AUTH_ONLY)
            self.assertFalse(v.issue)
            self.assertTrue(v.auth_without_issue and v.block_requested)

    def test_selected_current_foreign_original_orphans_ticket(self):
        for family in [4,6]:
            v=classify(family,self.scenario(original_selected=False))
            self.assertEqual(v.scope, SCOPE_REDIRECT_ONLY)
            self.assertTrue(v.issue and v.orphan_issue)
            self.assertFalse(v.attest or v.block_requested)

    def test_sibling_not_selected_not_an_evidence_of_system_allow(self):
        for family in [4,6]:
            v=classify(family,self.scenario(current_selected=False,original_selected=False))
            self.assertEqual(v.scope, SCOPE_NEITHER)
            self.assertFalse(v.issue or v.attest or v.block_requested)

    def test_udp_outside_tcp_scope_not_trusted(self):
        for family in [4,6]:
            v=classify(family,self.scenario(tcp=False))
            self.assertEqual(v.scope,SCOPE_UDP)
            self.assertFalse(v.issue or v.attest)

    def test_pid_epoch_reuse_never_claim_candidate(self):
        for family in [4,6]:
            for field in ("endpoint_owner_selected","epoch_match","start_key_match"):
                v=classify(family,self.scenario(**{field:False}))
                self.assertFalse(v.issue or v.attest)
                self.assertTrue(v.block_requested)

    def test_endpoint_aba_and_redirect_record_scope(self):
        for family in [4,6]:
            for field in ("endpoint_unique", "redirect_state_clean", "destination_valid"):
                v=classify(family,self.scenario(**{field:False}))
                self.assertFalse(v.issue or v.attest)

    def test_auth_source_evidence_missing(self):
        for family in [4,6]:
            for field in ("target_pid_match", "redirected_flag", "auth_callback_observed"):
                v=classify(family,self.scenario(**{field:False}))
                self.assertFalse(v.attest)

    def test_no_callback_does_not_mean_physical_block(self):
        v=classify(4,self.scenario(auth_callback_observed=False))
        self.assertTrue(v.issue)
        self.assertFalse(v.attest)
        self.assertFalse(v.block_requested)

    def test_health_loss_wfp_ssh_and_owner_death(self):
        for family in (4,6):
            for field in ("ssh_ok", "wfp_ok", "owner_alive_observed"):
                v=classify(family,self.scenario(**{field:False}))
                self.assertFalse(v.issue or v.attest)

    def test_missing_metadata_never_issues(self):
        self.assertFalse(classify(4,self.scenario(metadata_complete=False)).issue)

    def test_5tuple_identical_but_different_epoch_not_equivalent(self):
        a=classify(4,BASE)
        b=classify(4,self.scenario(epoch_match=False))
        self.assertTrue(a.attest)
        self.assertFalse(b.attest)

    def test_issue_mutants_all_killed_by_single_failing_witness(self):
        for f in ISSUE_REQUIRE:
            v=classify(4,self.scenario(**{f:False}))
            self.assertFalse(v.issue, f)
            relaxed = all(self.scenario(**{f:False}) & (1 << KEYS.index(k)) for k in ISSUE_REQUIRE if k!=f)
            self.assertTrue(relaxed, f)

    def test_auth_mutants_all_killed_by_single_failing_witness(self):
        for f in AUTH_EXTRA:
            mask=self.scenario(**{f:False})
            v=classify(4,mask)
            self.assertFalse(v.attest,f)
            relaxed=all(bit(mask,k) for k in ISSUE_REQUIRE+tuple(k for k in AUTH_EXTRA if k!=f))
            self.assertTrue(relaxed,f)

    def test_both_families_do_not_cross_join(self):
        self.assertNotEqual(classify(4,BASE).family,classify(6,BASE).family)
        self.assertEqual(classify(4,BASE).attest,classify(6,BASE).attest)

    def test_current_and_original_swap_is_observably_different(self):
        a=classify(4,self.scenario(current_selected=True,original_selected=False))
        b=classify(4,self.scenario(current_selected=False,original_selected=True))
        self.assertNotEqual((a.issue,a.block_requested),(b.issue,b.block_requested))

    def test_declared_source_pins_complete(self):
        self.assertEqual(len(PINS),4)
        self.assertEqual(set(map(len,PINS.values())),{40})

if __name__ == "__main__":
    unittest.main(verbosity=2)
