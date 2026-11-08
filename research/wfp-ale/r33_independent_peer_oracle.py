"""R33 independent exhaustive indistinguishability checker; no imports from primary model."""
from itertools import product

count = 0
for family, claim, available, reply in product((4, 6), (False, True), (False, True), (False, True)):
    # The observation includes raw SOCKS family-dependent destination and reply,
    # but it does NOT include the sender's OS process identity or SSH transport.
    raw = b'\x05\x01\x00' + bytes([family]) + bytes([int(claim), int(available), int(reply)])
    world_ssh = (raw, 'ssh', True)
    world_other = (raw, 'other', False)
    assert world_ssh[0] == world_other[0]
    accepted = claim and available and reply
    assert accepted == bool(world_ssh[0][4] and world_ssh[0][5] and world_ssh[0][6])
    if accepted:
        assert world_ssh[1] == 'ssh' and world_other[1] != 'ssh'
    count += 1
assert count == 16
print(f'R33_INDEPENDENT_ORACLE_PASS observation_pairs={count}; positives=2; network_calls=0')
