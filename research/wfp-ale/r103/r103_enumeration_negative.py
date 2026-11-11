#!/usr/bin/env python3
"""Independent R103 conservative tri-state model; no WFP or network access."""
from hashlib import sha256
from itertools import product


def classify(weight, visible, page_ok, baseline_ok):
    if not page_ok or not baseline_ok:
        return "UNKNOWN_ERROR"
    if visible and weight in ("HIGH", "TIE"):
        return "VISIBLE_CANDIDATE"
    # Even if no visible conflicts, enumeration suppresses unreadable filters.
    return "UNKNOWN_NO_VISIBLE"


rows = []
counts = {"UNKNOWN_ERROR": 0, "VISIBLE_CANDIDATE": 0, "UNKNOWN_NO_VISIBLE": 0}
for fam, stage, weight_idx, visible, page_ok, baseline_ok, hidden_high in product(range(2), range(2), range(4), range(2), range(2), range(2), range(2)):
    weight = ("LOW", "TIE", "HIGH", "NONE")[weight_idx]
    result = classify(weight, visible, page_ok, baseline_ok)
    counts[result] += 1
    rows.append(f"{fam}|{stage}|{weight}|{visible}|{page_ok}|{baseline_ok}|{hidden_high}|{result}")
    if page_ok and baseline_ok and hidden_high and not visible:
        assert result == "UNKNOWN_NO_VISIBLE"
    if not page_ok or not baseline_ok:
        assert result == "UNKNOWN_ERROR"
    assert result != "POLICY_SAFE"  # A management inventory never certifies safety.
assert len(rows) == 256
assert counts == {"UNKNOWN_ERROR": 192, "VISIBLE_CANDIDATE": 16, "UNKNOWN_NO_VISIBLE": 48}, counts
hash_ = sha256(("\n".join(rows) + "\n").encode()).hexdigest()
print(f"R103 PYTHON PASS: {len(rows)} states; counts={counts}; digest={hash_}")
print(next(r for r in rows if "|HIGH|1|1|1|0|VISIBLE_CANDIDATE" in r))
print(next(r for r in rows if "|NONE|0|1|1|1|UNKNOWN_NO_VISIBLE" in r))
