"""R186: deterministic, offline WFP inventory observation model. No Windows calls."""
import itertools
import json

KEYS = ("auth_v4", "auth_v6", "redirect_v4", "redirect_v6",
        "callout_auth_v4", "callout_auth_v6", "callout_redirect_v4", "callout_redirect_v6")


def schedules():
    return ("".join(map(str, seq)) for seq in itertools.combinations_with_replacement(range(3), len(KEYS)))


def record(mode, phase, index):
    if mode == "stable":
        epoch = "A"
    elif phase == 1:
        return None
    else:
        epoch = "A" if phase == 0 else "B"
    registered = not (mode == "unregistered" and phase == 2 and index >= 4)
    return {"key": KEYS[index], "epoch": epoch,
            "runtime_id": (100 if epoch == "A" else 200) + index,
            "registered": registered}


def calculate(mode, sequence, hidden_foreign, transaction):
    # Pinned read-only BFE transaction observes one phase, not an 8-step mixture.
    phases = [int(sequence[0])] * len(KEYS) if transaction else list(map(int, sequence))
    observed = [record(mode, phase, i) for i, phase in enumerate(phases)]
    all_present = all(x is not None for x in observed)
    all_registered = all(x is not None and (i < 4 or x["registered"])
                         for i, x in enumerate(observed))
    epochs = sorted({x["epoch"] for x in observed if x is not None})
    naive_green = all_present and all_registered
    # Only the described 8 owned objects are read. Even an ACID snapshot does
    # not establish classification results, effective policy or absence of
    # unreadable unrelated filters, or future uptime.
    return {"mode": mode, "sequence": sequence, "hidden_foreign": hidden_foreign,
            "transaction": transaction, "naive_green": naive_green,
            "read_ok": all_present, "registered": all_registered,
            "mixed_epochs": len(epochs) > 1,
            "observed_epochs": "".join(epochs),
            "status": "OWN_OBJECTS_SNAPSHOT_ONLY" if transaction and naive_green
                      else "NON_ATOMIC_OR_INCOMPLETE",
            "enforcement_proven": False,
            "continuous_coverage_proven": False}


def rows():
    for mode, sequence, hidden, txn in itertools.product(
            ("churn", "stable", "unregistered"), schedules(), (False, True), (False, True)):
        yield calculate(mode, sequence, hidden, txn)


if __name__ == "__main__":
    for row in rows():
        print(json.dumps(row, sort_keys=True, separators=(",", ":")))
