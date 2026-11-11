#!/usr/bin/env python3
"""Offline proof of a BFE monitoring observability cut; never calls WFP/Win32/network."""
from itertools import product
from hashlib import sha256

ROWS = []
for family, mask, ping, delivered in product((4, 6), range(16), (0, 1), (0, 1)):
    # Each bit is one of the four independent R19-owned ALE filter objects.
    complete = int(mask == 15)
    reported_ready = int(bool(ping))  # R19 heartbeat reads only Device::PING.
    missed = int(bool(reported_ready and not complete and not delivered))
    rowsig = f'{family}|{mask:04b}|{ping}|{delivered}|{complete}|{reported_ready}|{missed}'
    ROWS.append(rowsig)

assert len(ROWS) == 128
assert sum(int(row.split('|')[6]) for row in ROWS) == 30
assert sum(row.split('|')[4] == '1' for row in ROWS) == 8
assert sum(row.split('|')[5] == '1' for row in ROWS) == 64
# Counterexamples: identical observable (family, ping=1, no event), different real BFE inventory.
for family in (4, 6):
    unbroken = f'{family}|1111|1|0|1|1|0'
    absent = f'{family}|0000|1|0|0|1|1'
    assert unbroken in ROWS and absent in ROWS
# No claim of a real packet or actually missing filter is allowed here.
assert not any('PACKET_PASS' in row or 'DIRECT_OBSERVED' in row for row in ROWS)
print('R107 PY PASS states=128 missed_model=30 complete=8 ready=64')
print('SHA256=' + sha256(('\n'.join(ROWS)+'\n').encode()).hexdigest())
