#!/usr/bin/env python3
"""R161 offline negative-state oracle. This never calls WFP, a driver, or a network API."""
import itertools
import json
import subprocess
import sys
import unittest

SOURCE_PINS = {
    "kernel/src/redirect.rs": "a093f049d162987981a957aac90db1014bc6ff09",
    "kernel/src/handoff.rs": "e1d17217db50362ba9c4efc83af820b6beb094cf",
    "kernel/src/lib.rs": "53f5ce6faa0f9f591974287f38ea890cafeb0dd2",
    "broker.rs": "6163e84aea08ddde7e51a7fb94ccb6d68ae951fb",
    "policy_windows.rs": "acf60334320d970f58af3349ee75fbaa59826602",
}
EVENTS = ("ARM", "STOP", "BROKER_EXIT", "BROKER_RESTART",
          "LEASE_TIMEOUT_CHECK", "BFE_SESSION_LOST", "POLICY_REINSTALL", "PING")


def source_gate():
    root = "research/wfp-ale/kernel-r19/"
    src = {}
    for name, pin in SOURCE_PINS.items():
        path = root + name
        got = subprocess.check_output(["git", "rev-parse", "HEAD:" + path], text=True).strip()
        if got != pin:
            raise RuntimeError("source_pin_changed:" + path + ":" + got)
        src[name] = subprocess.check_output(["git", "show", "HEAD:" + path]).decode()
    redirect = src["kernel/src/redirect.rs"]
    handoff = src["kernel/src/handoff.rs"]
    broker = src["broker.rs"]
    policy = src["policy_windows.rs"]
    required = {
        "single_arm": "if r.configured||input.len()!=h::ARM_LEN",
        "arm_sets_latch": "r.configured=true;r.armed=true",
        "loss_does_not_clear_latch": "r.armed=false;r.book.kill();",
        "stop_calls_loss": "if code==h::STOP{lose();return super::SUCCESS;}",
        "ready_failure_loses": "{lose();return false;}true",
        "broker_exit_loses": "if (*ROUTE.0.get()).pid==pid{lose();}",
        "book_kill_latches": "pub fn kill(&mut self) {self.lost=true;",
        "book_initialize_not_reset": "if self.session!=[0;16] || session==[0;16] {self.lost=true;return false;}",
        "broker_ping": "d.command(handoff::PING,&[])",
        "policy_dynamic": "session.flags=FWPM_SESSION_FLAG_DYNAMIC",
    }
    source = {"single_arm": redirect, "arm_sets_latch": redirect,
              "loss_does_not_clear_latch": redirect, "stop_calls_loss": redirect,
              "ready_failure_loses": redirect, "broker_exit_loses": redirect,
              "book_kill_latches": handoff, "book_initialize_not_reset": handoff,
              "broker_ping": broker, "policy_dynamic": policy}
    for k, needle in required.items():
        if needle not in source[k]:
            raise RuntimeError("source_contract_changed:" + k)
    # If a future change introduces a supported reset, investigate instead of claiming impossibility.
    if "r.configured=false" in redirect or "self.lost=false" in handoff:
        raise RuntimeError("reset_added_recheck_model")
    return True


def simulate(events):
    # Exact claim: within ONE loaded R19 instance, with no prohibited driver reset.
    state = dict(configured=False, armed=False, lost=False, broker=True,
                 bfe=True, epoch=0, owner_epoch=-1,
                 arm_ok=0, arm_denied=0, ping_ok=0, ping_denied=0, ping_without_bfe=0,
                 reinstalled_after_terminal=0)
    for event in events:
        if event == "ARM":
            if state["configured"] or not state["broker"] or state["lost"]:
                state["arm_denied"] += 1
            else:
                state["configured"] = state["armed"] = True
                state["owner_epoch"] = state["epoch"]
                state["arm_ok"] += 1
        elif event == "STOP":
            # Only the exact original broker can call a successful STOP.
            if state["configured"] and state["broker"] and state["epoch"] == state["owner_epoch"]:
                state["armed"] = False
                state["lost"] = True
        elif event == "BROKER_EXIT":
            if state["broker"] and state["configured"] and state["epoch"] == state["owner_epoch"]:
                state["armed"] = False
                state["lost"] = True
            state["broker"] = False
        elif event == "BROKER_RESTART":
            if not state["broker"]:
                state["epoch"] += 1
                state["broker"] = True
        elif event == "LEASE_TIMEOUT_CHECK":
            if state["configured"] and state["armed"]:
                state["armed"] = False
                state["lost"] = True
        elif event == "BFE_SESSION_LOST":
            state["bfe"] = False
        elif event == "POLICY_REINSTALL":
            state["bfe"] = True  # optimistic user-mode BFE recreation; not runtime proof
            state["reinstalled_after_terminal"] += int(state["configured"] and state["lost"])
        elif event == "PING":
            if state["armed"] and not state["lost"] and state["broker"] and state["epoch"] == state["owner_epoch"]:
                state["ping_ok"] += 1  # R19 PING has no BFE policy query
                state["ping_without_bfe"] += int(not state["bfe"])
            else:
                state["ping_denied"] += 1
        else:
            raise ValueError(event)
        if state["arm_ok"] > 1 or (state["lost"] and state["armed"]):
            raise AssertionError("model_invariant_violation")
    return state


def matrix():
    result = dict(traces=0, terminal=0, rejected_rearm=0, reinstalled_terminal=0,
                  bfe_missing_ping_ok=0, configured_and_not_armed=0)
    for size in range(6):
        for events in itertools.product(EVENTS, repeat=size):
            s = simulate(events)
            result["traces"] += 1
            result["terminal"] += int(s["configured"] and s["lost"])
            result["rejected_rearm"] += int(s["lost"] and s["arm_denied"] > 0)
            result["reinstalled_terminal"] += int(s["reinstalled_after_terminal"] > 0)
            result["bfe_missing_ping_ok"] += int(s["ping_without_bfe"] > 0)
            result["configured_and_not_armed"] += int(s["configured"] and not s["armed"])
    return result


class Negative(unittest.TestCase):
    def test_stop_cannot_rearm(self):
        s = simulate(("ARM", "STOP", "ARM"))
        self.assertEqual((s["arm_ok"], s["arm_denied"], s["lost"]), (1, 1, True))

    def test_expired_lease_cannot_rearm(self):
        s = simulate(("ARM", "LEASE_TIMEOUT_CHECK", "ARM"))
        self.assertEqual((s["arm_ok"], s["arm_denied"], s["lost"]), (1, 1, True))

    def test_broker_restart_cannot_rearm(self):
        s = simulate(("ARM", "BROKER_EXIT", "BROKER_RESTART", "ARM"))
        self.assertEqual((s["arm_ok"], s["arm_denied"], s["lost"]), (1, 1, True))

    def test_policy_reinstall_does_not_rearm_kernel(self):
        s = simulate(("ARM", "BFE_SESSION_LOST", "STOP", "POLICY_REINSTALL", "ARM"))
        self.assertTrue(s["bfe"] and s["lost"] and not s["armed"])
        self.assertEqual(s["arm_denied"], 1)

    def test_ping_does_not_attest_bfe(self):
        s = simulate(("ARM", "BFE_SESSION_LOST", "PING"))
        self.assertEqual(s["ping_ok"], 1)
        self.assertFalse(s["bfe"])

    def test_no_arm_without_prior_broker(self):
        s = simulate(("BROKER_EXIT", "ARM"))
        self.assertEqual((s["arm_ok"], s["arm_denied"]), (0, 1))

    def test_latched_loss_is_monotonic(self):
        self.assertEqual(matrix()["traces"], 37449)

    def test_gate_has_no_python_assert_optimization_bypass(self):
        import inspect
        self.assertNotIn("assert ", inspect.getsource(source_gate))


if __name__ == "__main__":
    if sys.argv[1:] == ["--matrix"]:
        print(json.dumps(matrix(), sort_keys=True))
    elif sys.argv[1:] == ["--source-gate"]:
        print(json.dumps({"pass": source_gate(), "blobs": SOURCE_PINS}, sort_keys=True))
    elif sys.argv[1:] == ["--test"]:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    else:
        sys.exit("usage: --matrix | --test | --source-gate")
