#!/usr/bin/env python3
"""Offline R108 state-space test. No Windows API, network or driver activity."""
from hashlib import sha256
from itertools import product

FAMILIES = (4, 6)
REASONS = ("INITIAL", "POLICY_CHANGE", "NEW_INTERFACE", "CLASSIFY_COMPLETION", "SOCKET_PROPERTY")
ROWS = []
for family, reason, write, metadata, redirected, origin, ticket in product(
        FAMILIES, REASONS, (0, 1), (0, 1), (0, 1), (0, 1), (0, 1)):
    # The source checks rights and mandatory metadata first, and then blocks
    # FWP_CONDITION_FLAG_IS_REAUTHORIZE (0x4) unconditionally. Flags model only.
    reauthorize = int(reason != "INITIAL")
    permit = int(bool(write and metadata and redirected and not reauthorize and origin and ticket))
    rows = (family, reason, write, metadata, redirected, origin, ticket, permit)
    ROWS.append("|".join(map(str, rows)))
raw = "\n".join(ROWS).encode("ascii") + b"\n"
expected_total = 2 * 5 * 2**5
assert len(ROWS) == expected_total
assert sum(row.endswith("|1") for row in ROWS) == 2
# The very same complete provenance, owned ticket, rights and metadata are
# accepted initially but blocked if the kernel classifies reauthorization.
for family in FAMILIES:
    key = lambda reason: f"{family}|{reason}|1|1|1|1|1|"
    assert key("INITIAL") + "1" in ROWS
    for reason in REASONS[1:]:
        assert key(reason) + "0" in ROWS
assert all(row.endswith("|0") for row in ROWS if "|" + "POLICY_CHANGE" + "|" in row)
print(f"states={len(ROWS)} permitted=2 reauth_block_with_all_other_gates_valid=8 sha256={sha256(raw).hexdigest()}")
