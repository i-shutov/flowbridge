#!/usr/bin/env python3
"""R144: adversarial in-memory mutation of a real R143 compiled blueprint.

No network, sockets, BFE, WFP object mutation, driver or process operations.
"""
import copy
import importlib.util
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / "r143" / "r143_policy_compiler.py"
spec = importlib.util.spec_from_file_location("r143_compiler", SOURCE)
compiler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compiler)

CASES = (
    ("boot_false_to_zero", ("boot_handoff", "persistent_flag_combined"), 0, True),
    ("ready_proven_false_to_zero", ("state_machine", "ready_observations_proven"), 0, True),
    ("model_only_true_to_one", ("state_machine", "state_names_are_model_only"), 1, True),
    ("boot_false_to_one", ("boot_handoff", "persistent_flag_combined"), 1, False),
    ("ready_proven_false_to_one", ("state_machine", "ready_observations_proven"), 1, False),
    ("model_only_true_to_zero", ("state_machine", "state_names_are_model_only"), 0, False),
    ("boot_false_to_string", ("boot_handoff", "persistent_flag_combined"), "false", False),
    ("model_only_true_to_null", ("state_machine", "state_names_are_model_only"), None, False),
)

def main():
    pristine = compiler.compile_from_bytes()
    compiler.validate_blueprint(pristine)
    for label, path, replacement, legacy_false_accept in CASES:
        forged = copy.deepcopy(pristine)
        pointer = forged
        for key in path[:-1]:
            pointer = pointer[key]
        pointer[path[-1]] = replacement
        forged["blueprint_sha256"] = compiler.digest(
            {k: v for k, v in forged.items() if k != "blueprint_sha256"})
        legacy = forged[path[0]] == pristine[path[0]]
        assert legacy is legacy_false_accept, label + ": unexpected legacy result"
        try:
            compiler.validate_blueprint(forged)
        except compiler.GateError:
            accepted = False
        else:
            accepted = True
        assert not accepted, label + ": tampered rehashed blueprint accepted"
        print(f"{label}|old={int(legacy)}|strict={int(accepted)}")
    print("negative_regressions=8; old_false_accept=3; strict_false_accept=0; native_wfp_executed=false")

if __name__ == "__main__":
    main()
