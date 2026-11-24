"""Bounded byte fixtures only; no Windows or pointer access."""
import hashlib
import itertools


def old(layer, raw):
    n = {4: 16, 6: 28}[layer]
    if len(raw) < n:
        return 'EXTENT'
    return 'MATCH' if int.from_bytes(raw[:2], 'little') == {4: 2, 6: 23}[layer] else 'REJECT'


def staged(layer, raw):
    if len(raw) < 2:
        return 'EXTENT'
    if int.from_bytes(raw[:2], 'little') != {4: 2, 6: 23}[layer]:
        return 'REJECT'
    return 'MATCH' if len(raw) >= {4: 16, 6: 28}[layer] else 'EXTENT'


def main():
    rows = []
    for layer, af, n in itertools.product((4, 6), (2, 23, 99), (1, 2, 16, 28, 128)):
        raw = (af.to_bytes(2, 'little') + bytes(126))[:n]
        rows.append(f'{layer},{af},{n},{old(layer, raw)},{staged(layer, raw)}\n')
    assert old(6, b'\x02\x00' + bytes(14)) == 'EXTENT'
    assert staged(6, b'\x02\x00' + bytes(14)) == 'REJECT'
    assert old(6, b'\x17\x00' + bytes(26)) == staged(6, b'\x17\x00' + bytes(26)) == 'MATCH'
    assert old(4, b'\x17\x00' + bytes(26)) == staged(4, b'\x17\x00' + bytes(26)) == 'REJECT'
    assert sum(r.endswith('EXTENT,REJECT\n') for r in rows) == 6
    print(len(rows), hashlib.sha256(''.join(rows).encode()).hexdigest())


if __name__ == '__main__':
    main()
